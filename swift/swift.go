// Package swift provides an interface to the Swift object storage system
package swift

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"path"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/ncw/rclone/fs"
	"github.com/ncw/swift"
	"github.com/spf13/pflag"
)

// Globals
var (
	chunkSize = fs.SizeSuffix(5 * 1024 * 1024 * 1024)
)

// Register with Fs
func init() {
	fs.Register(&fs.Info{
		Name:  "swift",
		NewFs: NewFs,
		Options: []fs.Option{{
			Name: "user",
			Help: "User name to log in.",
		}, {
			Name: "key",
			Help: "API key or password.",
		}, {
			Name: "auth",
			Help: "Authentication URL for server.",
			Examples: []fs.OptionExample{{
				Help:  "Rackspace US",
				Value: "https://auth.api.rackspacecloud.com/v1.0",
			}, {
				Help:  "Rackspace UK",
				Value: "https://lon.auth.api.rackspacecloud.com/v1.0",
			}, {
				Help:  "Rackspace v2",
				Value: "https://identity.api.rackspacecloud.com/v2.0",
			}, {
				Help:  "Memset Memstore UK",
				Value: "https://auth.storage.memset.com/v1.0",
			}, {
				Help:  "Memset Memstore UK v2",
				Value: "https://auth.storage.memset.com/v2.0",
			}},
		}, {
			Name: "tenant",
			Help: "Tenant name - optional",
		}, {
			Name: "region",
			Help: "Region name - optional",
		},
		},
	})
	// snet     = flag.Bool("swift-snet", false, "Use internal service network") // FIXME not implemented
	pflag.VarP(&chunkSize, "swift-chunk-size", "", "Above this size files will be chunked into a _segments container.")
}

// FsSwift represents a remote swift server
type FsSwift struct {
	name              string           // name of this remote
	c                 swift.Connection // the connection to the swift server
	container         string           // the container we are working on
	segmentsContainer string           // container to store the segments (if any) in
	root              string           // the path we are working on if any
}

// FsObjectSwift describes a swift object
//
// Will definitely have info but maybe not meta
type FsObjectSwift struct {
	swift   *FsSwift       // what this object is part of
	remote  string         // The remote path
	info    swift.Object   // Info from the swift object if known
	headers *swift.Headers // The object headers if known
}

// ------------------------------------------------------------

// Name of the remote (as passed into NewFs)
func (f *FsSwift) Name() string {
	return f.name
}

// Root of the remote (as passed into NewFs)
func (f *FsSwift) Root() string {
	if f.root == "" {
		return f.container
	}
	return f.container + "/" + f.root
}

// String converts this FsSwift to a string
func (f *FsSwift) String() string {
	if f.root == "" {
		return fmt.Sprintf("Swift container %s", f.container)
	}
	return fmt.Sprintf("Swift container %s path %s", f.container, f.root)
}

// Pattern to match a swift path
var matcher = regexp.MustCompile(`^([^/]*)(.*)$`)

// parseParse parses a swift 'url'
func parsePath(path string) (container, directory string, err error) {
	parts := matcher.FindStringSubmatch(path)
	if parts == nil {
		err = fmt.Errorf("Couldn't find container in swift path %q", path)
	} else {
		container, directory = parts[1], parts[2]
		directory = strings.Trim(directory, "/")
	}
	return
}

// swiftConnection makes a connection to swift
func swiftConnection(name string) (*swift.Connection, error) {
	userName := fs.ConfigFile.MustValue(name, "user")
	if userName == "" {
		return nil, errors.New("user not found")
	}
	apiKey := fs.ConfigFile.MustValue(name, "key")
	if apiKey == "" {
		return nil, errors.New("key not found")
	}
	authURL := fs.ConfigFile.MustValue(name, "auth")
	if authURL == "" {
		return nil, errors.New("auth not found")
	}
	c := &swift.Connection{
		UserName:       userName,
		ApiKey:         apiKey,
		AuthUrl:        authURL,
		UserAgent:      fs.UserAgent,
		Tenant:         fs.ConfigFile.MustValue(name, "tenant"),
		Region:         fs.ConfigFile.MustValue(name, "region"),
		ConnectTimeout: 10 * fs.Config.ConnectTimeout, // Use the timeouts in the transport
		Timeout:        10 * fs.Config.Timeout,        // Use the timeouts in the transport
		Transport:      fs.Config.Transport(),
	}
	err := c.Authenticate()
	if err != nil {
		return nil, err
	}
	return c, nil
}

// NewFs contstructs an FsSwift from the path, container:path
func NewFs(name, root string) (fs.Fs, error) {
	container, directory, err := parsePath(root)
	if err != nil {
		return nil, err
	}
	c, err := swiftConnection(name)
	if err != nil {
		return nil, err
	}
	f := &FsSwift{
		name:              name,
		c:                 *c,
		container:         container,
		segmentsContainer: ".segments_" + container,
		root:              directory,
	}
	if f.root != "" {
		f.root += "/"
		// Check to see if the object exists
		_, _, err = f.c.Object(container, directory)
		if err == nil {
			remote := path.Base(directory)
			f.root = path.Dir(directory)
			if f.root == "." {
				f.root = ""
			} else {
				f.root += "/"
			}
			obj := f.NewFsObject(remote)
			// return a Fs Limited to this object
			return fs.NewLimited(f, obj), nil
		}
	}
	return f, nil
}

// Return an FsObject from a path
//
// May return nil if an error occurred
func (f *FsSwift) newFsObjectWithInfo(remote string, info *swift.Object) fs.Object {
	o := &FsObjectSwift{
		swift:  f,
		remote: remote,
	}
	if info != nil {
		// Set info but not headers
		o.info = *info
	} else {
		err := o.readMetaData() // reads info and headers, returning an error
		if err != nil {
			fs.Debug(o, "Failed to read metadata: %s", err)
			return nil
		}
	}
	return o
}

// NewFsObject returns an FsObject from a path
//
// May return nil if an error occurred
func (f *FsSwift) NewFsObject(remote string) fs.Object {
	return f.newFsObjectWithInfo(remote, nil)
}

// listFn is called from list and listContainerRoot to handle an object
type listFn func(string, *swift.Object) error

// listContainerRoot lists the objects into the function supplied from
// the container and root supplied
//
// If directories is set it only sends directories
func (f *FsSwift) listContainerRoot(container, root string, directories bool, fn listFn) error {
	// Options for ObjectsWalk
	opts := swift.ObjectsOpts{
		Prefix: root,
		Limit:  256,
	}
	if directories {
		opts.Delimiter = '/'
	}
	rootLength := len(root)
	return f.c.ObjectsWalk(container, &opts, func(opts *swift.ObjectsOpts) (interface{}, error) {
		objects, err := f.c.Objects(container, opts)
		if err == nil {
			for i := range objects {
				object := &objects[i]
				// FIXME if there are no directories, swift gives back the files for some reason!
				if directories {
					if !strings.HasSuffix(object.Name, "/") {
						continue
					}
					object.Name = object.Name[:len(object.Name)-1]
				}
				if !strings.HasPrefix(object.Name, root) {
					fs.Log(f, "Odd name received %q", object.Name)
					continue
				}
				remote := object.Name[rootLength:]
				err = fn(remote, object)
				if err != nil {
					break
				}
			}
		}
		return objects, err
	})
}

// list the objects into the function supplied
//
// If directories is set it only sends directories
func (f *FsSwift) list(directories bool, fn listFn) {
	err := f.listContainerRoot(f.container, f.root, directories, fn)
	if err != nil {
		fs.Stats.Error()
		fs.ErrorLog(f, "Couldn't read container %q: %s", f.container, err)
	}
}

// List walks the path returning a channel of FsObjects
func (f *FsSwift) List() fs.ObjectsChan {
	out := make(fs.ObjectsChan, fs.Config.Checkers)
	if f.container == "" {
		// Return no objects at top level list
		close(out)
		fs.Stats.Error()
		fs.ErrorLog(f, "Can't list objects at root - choose a container using lsd")
	} else {
		// List the objects
		go func() {
			defer close(out)
			f.list(false, func(remote string, object *swift.Object) error {
				if o := f.newFsObjectWithInfo(remote, object); o != nil {
					// Do full metadata read on 0 size objects which might be manifest files
					if o.Size() == 0 {
						err := o.(*FsObjectSwift).readMetaData()
						if err != nil {
							fs.Debug(o, "Failed to read metadata: %v", err)
						}
					}
					out <- o
				}
				return nil
			})
		}()
	}
	return out
}

// ListDir lists the containers
func (f *FsSwift) ListDir() fs.DirChan {
	out := make(fs.DirChan, fs.Config.Checkers)
	if f.container == "" {
		// List the containers
		go func() {
			defer close(out)
			containers, err := f.c.ContainersAll(nil)
			if err != nil {
				fs.Stats.Error()
				fs.ErrorLog(f, "Couldn't list containers: %v", err)
			} else {
				for _, container := range containers {
					out <- &fs.Dir{
						Name:  container.Name,
						Bytes: container.Bytes,
						Count: container.Count,
					}
				}
			}
		}()
	} else {
		// List the directories in the path in the container
		go func() {
			defer close(out)
			f.list(true, func(remote string, object *swift.Object) error {
				out <- &fs.Dir{
					Name:  remote,
					Bytes: object.Bytes,
					Count: 0,
				}
				return nil
			})
		}()
	}
	return out
}

// Put the object into the container
//
// Copy the reader in to the new object which is returned
//
// The new object may have been created if an error is returned
func (f *FsSwift) Put(in io.Reader, remote string, modTime time.Time, size int64) (fs.Object, error) {
	// Temporary FsObject under construction
	fs := &FsObjectSwift{swift: f, remote: remote}
	return fs, fs.Update(in, modTime, size)
}

// Mkdir creates the container if it doesn't exist
func (f *FsSwift) Mkdir() error {
	return f.c.ContainerCreate(f.container, nil)
}

// Rmdir deletes the container
//
// Returns an error if it isn't empty
func (f *FsSwift) Rmdir() error {
	return f.c.ContainerDelete(f.container)
}

// Precision of the remote
func (f *FsSwift) Precision() time.Duration {
	return time.Nanosecond
}

// Copy src to this remote using server side copy operations.
//
// This is stored with the remote path given
//
// It returns the destination Object and a possible error
//
// Will only be called if src.Fs().Name() == f.Name()
//
// If it isn't possible then return fs.ErrorCantCopy
func (f *FsSwift) Copy(src fs.Object, remote string) (fs.Object, error) {
	srcObj, ok := src.(*FsObjectSwift)
	if !ok {
		fs.Debug(src, "Can't copy - not same remote type")
		return nil, fs.ErrorCantCopy
	}
	srcFs := srcObj.swift
	_, err := f.c.ObjectCopy(srcFs.container, srcFs.root+srcObj.remote, f.container, f.root+remote, nil)
	if err != nil {
		return nil, err
	}
	return f.NewFsObject(remote), nil
}

// ------------------------------------------------------------

// Fs returns the parent Fs
func (o *FsObjectSwift) Fs() fs.Fs {
	return o.swift
}

// Return a string version
func (o *FsObjectSwift) String() string {
	if o == nil {
		return "<nil>"
	}
	return o.remote
}

// Remote returns the remote path
func (o *FsObjectSwift) Remote() string {
	return o.remote
}

// Md5sum returns the Md5sum of an object returning a lowercase hex string
func (o *FsObjectSwift) Md5sum() (string, error) {
	isManifest, err := o.isManifestFile()
	if err != nil {
		return "", err
	}
	if isManifest {
		fs.Debug(o, "Returning empty Md5sum for swift manifest file")
		return "", nil
	}
	return strings.ToLower(o.info.Hash), nil
}

// isManifestFile checks for manifest header
func (o *FsObjectSwift) isManifestFile() (bool, error) {
	err := o.readMetaData()
	if err != nil {
		if err == swift.ObjectNotFound {
			return false, nil
		}
		return false, err
	}
	_, isManifestFile := (*o.headers)["X-Object-Manifest"]
	return isManifestFile, nil
}

// Size returns the size of an object in bytes
func (o *FsObjectSwift) Size() int64 {
	return o.info.Bytes
}

// readMetaData gets the metadata if it hasn't already been fetched
//
// it also sets the info
func (o *FsObjectSwift) readMetaData() (err error) {
	if o.headers != nil {
		return nil
	}
	info, h, err := o.swift.c.Object(o.swift.container, o.swift.root+o.remote)
	if err != nil {
		return err
	}
	o.info = info
	o.headers = &h
	return nil
}

// ModTime returns the modification time of the object
//
//
// It attempts to read the objects mtime and if that isn't present the
// LastModified returned in the http headers
func (o *FsObjectSwift) ModTime() time.Time {
	err := o.readMetaData()
	if err != nil {
		fs.Debug(o, "Failed to read metadata: %s", err)
		return o.info.LastModified
	}
	modTime, err := o.headers.ObjectMetadata().GetModTime()
	if err != nil {
		// fs.Log(o, "Failed to read mtime from object: %s", err)
		return o.info.LastModified
	}
	return modTime
}

// SetModTime sets the modification time of the local fs object
func (o *FsObjectSwift) SetModTime(modTime time.Time) {
	err := o.readMetaData()
	if err != nil {
		fs.Stats.Error()
		fs.ErrorLog(o, "Failed to read metadata: %s", err)
		return
	}
	meta := o.headers.ObjectMetadata()
	meta.SetModTime(modTime)
	newHeaders := meta.ObjectHeaders()
	for k, v := range newHeaders {
		(*o.headers)[k] = v
	}
	err = o.swift.c.ObjectUpdate(o.swift.container, o.swift.root+o.remote, newHeaders)
	if err != nil {
		fs.Stats.Error()
		fs.ErrorLog(o, "Failed to update remote mtime: %s", err)
	}
}

// Storable returns if this object is storable
func (o *FsObjectSwift) Storable() bool {
	return true
}

// Open an object for read
func (o *FsObjectSwift) Open() (in io.ReadCloser, err error) {
	in, _, err = o.swift.c.ObjectOpen(o.swift.container, o.swift.root+o.remote, true, nil)
	return
}

// min returns the smallest of x, y
func min(x, y int64) int64 {
	if x < y {
		return x
	}
	return y
}

// removeSegments removes any old segments from o
//
// if except is passed in then segments with that prefix won't be deleted
func (o *FsObjectSwift) removeSegments(except string) error {
	segmentsRoot := o.swift.root + o.remote + "/"
	err := o.swift.listContainerRoot(o.swift.segmentsContainer, segmentsRoot, false, func(remote string, object *swift.Object) error {
		if except != "" && strings.HasPrefix(remote, except) {
			// fs.Debug(o, "Ignoring current segment file %q in container %q", segmentsRoot+remote, o.swift.segmentsContainer)
			return nil
		}
		segmentPath := segmentsRoot + remote
		fs.Debug(o, "Removing segment file %q in container %q", segmentPath, o.swift.segmentsContainer)
		return o.swift.c.ObjectDelete(o.swift.segmentsContainer, segmentPath)
	})
	if err != nil {
		return err
	}
	// remove the segments container if empty, ignore errors
	err = o.swift.c.ContainerDelete(o.swift.segmentsContainer)
	if err == nil {
		fs.Debug(o, "Removed empty container %q", o.swift.segmentsContainer)
	}
	return nil
}

// updateChunks updates the existing object using chunks to a separate
// container.  It returns a string which prefixes current segments.
func (o *FsObjectSwift) updateChunks(in io.Reader, headers swift.Headers, size int64) (string, error) {
	// Create the segmentsContainer if it doesn't exist
	err := o.swift.c.ContainerCreate(o.swift.segmentsContainer, nil)
	if err != nil {
		return "", err
	}
	// Upload the chunks
	left := size
	i := 0
	uniquePrefix := fmt.Sprintf("%s/%d", swift.TimeToFloatString(time.Now()), size)
	segmentsPath := fmt.Sprintf("%s%s/%s", o.swift.root, o.remote, uniquePrefix)
	for left > 0 {
		n := min(left, int64(chunkSize))
		headers["Content-Length"] = strconv.FormatInt(n, 10) // set Content-Length as we know it
		segmentReader := io.LimitReader(in, n)
		segmentPath := fmt.Sprintf("%s/%08d", segmentsPath, i)
		fs.Debug(o, "Uploading segment file %q into %q", segmentPath, o.swift.segmentsContainer)
		_, err := o.swift.c.ObjectPut(o.swift.segmentsContainer, segmentPath, segmentReader, true, "", "", headers)
		if err != nil {
			return "", err
		}
		left -= n
		i++
	}
	// Upload the manifest
	headers["X-Object-Manifest"] = fmt.Sprintf("%s/%s", o.swift.segmentsContainer, segmentsPath)
	headers["Content-Length"] = "0" // set Content-Length as we know it
	emptyReader := bytes.NewReader(nil)
	manifestName := o.swift.root + o.remote
	_, err = o.swift.c.ObjectPut(o.swift.container, manifestName, emptyReader, true, "", "", headers)
	return uniquePrefix + "/", err
}

// Update the object with the contents of the io.Reader, modTime and size
//
// The new object may have been created if an error is returned
func (o *FsObjectSwift) Update(in io.Reader, modTime time.Time, size int64) error {
	// Note whether this has a manifest before starting
	isManifest, err := o.isManifestFile()
	if err != nil {
		return err
	}

	// Set the mtime
	m := swift.Metadata{}
	m.SetModTime(modTime)
	headers := m.ObjectHeaders()
	uniquePrefix := ""
	if size > int64(chunkSize) {
		uniquePrefix, err = o.updateChunks(in, headers, size)
		if err != nil {
			return err
		}
	} else {
		headers["Content-Length"] = strconv.FormatInt(size, 10) // set Content-Length as we know it
		_, err := o.swift.c.ObjectPut(o.swift.container, o.swift.root+o.remote, in, true, "", "", headers)
		if err != nil {
			return err
		}
	}

	// If file was a manifest then remove old/all segments
	if isManifest {
		err = o.removeSegments(uniquePrefix)
		if err != nil {
			fs.Log(o, "Failed to remove old segments - carrying on with upload: %v", err)
		}
	}

	// Read the metadata from the newly created object
	o.headers = nil // wipe old metadata
	return o.readMetaData()
}

// Remove an object
func (o *FsObjectSwift) Remove() error {
	isManifestFile, err := o.isManifestFile()
	if err != nil {
		return err
	}
	// Remove file/manifest first
	err = o.swift.c.ObjectDelete(o.swift.container, o.swift.root+o.remote)
	if err != nil {
		return err
	}
	// ...then segments if required
	if isManifestFile {
		err = o.removeSegments("")
		if err != nil {
			return err
		}
	}
	return nil
}

// Check the interfaces are satisfied
var _ fs.Fs = &FsSwift{}
var _ fs.Copier = &FsSwift{}
var _ fs.Object = &FsObjectSwift{}
