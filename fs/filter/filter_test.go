package filter

import (
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ncw/rclone/fs"
	"github.com/ncw/rclone/fstest/mockobject"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewFilterDefault(t *testing.T) {
	f, err := NewFilter(nil)
	require.NoError(t, err)
	assert.False(t, f.Opt.DeleteExcluded)
	assert.Equal(t, fs.SizeSuffix(-1), f.Opt.MinSize)
	assert.Equal(t, fs.SizeSuffix(-1), f.Opt.MaxSize)
	assert.Len(t, f.fileRules.rules, 0)
	assert.Len(t, f.dirRules.rules, 0)
	assert.Nil(t, f.files)
	assert.True(t, f.InActive())
}

// testFile creates a temp file with the contents
func testFile(t *testing.T, contents string) string {
	out, err := ioutil.TempFile("", "filter_test")
	require.NoError(t, err)
	defer func() {
		err := out.Close()
		require.NoError(t, err)
	}()
	_, err = out.Write([]byte(contents))
	require.NoError(t, err)
	s := out.Name()
	return s
}

func TestNewFilterFull(t *testing.T) {
	Opt := DefaultOpt

	mins := fs.SizeSuffix(100 * 1024)
	maxs := fs.SizeSuffix(1000 * 1024)

	// Set up the input
	Opt.DeleteExcluded = true
	Opt.FilterRule = []string{"- filter1", "- filter1b"}
	Opt.FilterFrom = []string{testFile(t, "#comment\n+ filter2\n- filter3\n")}
	Opt.ExcludeRule = []string{"exclude1"}
	Opt.ExcludeFrom = []string{testFile(t, "#comment\nexclude2\nexclude3\n")}
	Opt.IncludeRule = []string{"include1"}
	Opt.IncludeFrom = []string{testFile(t, "#comment\ninclude2\ninclude3\n")}
	Opt.FilesFrom = []string{testFile(t, "#comment\nfiles1\nfiles2\n")}
	Opt.MinSize = mins
	Opt.MaxSize = maxs

	rm := func(p string) {
		err := os.Remove(p)
		if err != nil {
			t.Logf("error removing %q: %v", p, err)
		}
	}
	// Reset the input
	defer func() {
		rm(Opt.FilterFrom[0])
		rm(Opt.ExcludeFrom[0])
		rm(Opt.IncludeFrom[0])
		rm(Opt.FilesFrom[0])
	}()

	f, err := NewFilter(&Opt)
	require.NoError(t, err)
	assert.True(t, f.Opt.DeleteExcluded)
	assert.Equal(t, f.Opt.MinSize, mins)
	assert.Equal(t, f.Opt.MaxSize, maxs)
	got := f.DumpFilters()
	want := `--- File filter rules ---
+ (^|/)include1$
+ (^|/)include2$
+ (^|/)include3$
- (^|/)exclude1$
- (^|/)exclude2$
- (^|/)exclude3$
- (^|/)filter1$
- (^|/)filter1b$
+ (^|/)filter2$
- (^|/)filter3$
- ^.*$
--- Directory filter rules ---
+ ^.*$
- ^.*$`
	assert.Equal(t, want, got)
	assert.Len(t, f.files, 2)
	for _, name := range []string{"files1", "files2"} {
		_, ok := f.files[name]
		if !ok {
			t.Errorf("Didn't find file %q in f.files", name)
		}
	}
	assert.False(t, f.InActive())
}

type includeTest struct {
	in      string
	size    int64
	modTime int64
	want    bool
}

func testInclude(t *testing.T, f *Filter, tests []includeTest) {
	for _, test := range tests {
		got := f.Include(test.in, test.size, time.Unix(test.modTime, 0))
		assert.Equal(t, test.want, got, fmt.Sprintf("in=%q, size=%v, modTime=%v", test.in, test.size, time.Unix(test.modTime, 0)))
	}
}

type includeDirTest struct {
	in   string
	want bool
}

func testDirInclude(t *testing.T, f *Filter, tests []includeDirTest) {
	for _, test := range tests {
		got, err := f.IncludeDirectory(nil)(test.in)
		require.NoError(t, err)
		assert.Equal(t, test.want, got, test.in)
	}
}

func TestNewFilterIncludeFiles(t *testing.T) {
	f, err := NewFilter(nil)
	require.NoError(t, err)
	err = f.AddFile("file1.jpg")
	require.NoError(t, err)
	err = f.AddFile("/file2.jpg")
	require.NoError(t, err)
	assert.Equal(t, FilesMap{
		"file1.jpg": {},
		"file2.jpg": {},
	}, f.files)
	assert.Equal(t, FilesMap{}, f.dirs)
	testInclude(t, f, []includeTest{
		{"file1.jpg", 0, 0, true},
		{"file2.jpg", 1, 0, true},
		{"potato/file2.jpg", 2, 0, false},
		{"file3.jpg", 3, 0, false},
	})
	assert.False(t, f.InActive())
}

func TestNewFilterIncludeFilesDirs(t *testing.T) {
	f, err := NewFilter(nil)
	require.NoError(t, err)
	for _, path := range []string{
		"path/to/dir/file1.png",
		"/path/to/dir/file2.png",
		"/path/to/file3.png",
		"/path/to/dir2/file4.png",
	} {
		err = f.AddFile(path)
		require.NoError(t, err)
	}
	assert.Equal(t, FilesMap{
		"path":         {},
		"path/to":      {},
		"path/to/dir":  {},
		"path/to/dir2": {},
	}, f.dirs)
	testDirInclude(t, f, []includeDirTest{
		{"path", true},
		{"path/to", true},
		{"path/to/", true},
		{"/path/to", true},
		{"/path/to/", true},
		{"path/to/dir", true},
		{"path/to/dir2", true},
		{"path/too", false},
		{"path/three", false},
		{"four", false},
	})
}

func TestNewFilterHaveFilesFrom(t *testing.T) {
	f, err := NewFilter(nil)
	require.NoError(t, err)

	assert.Equal(t, false, f.HaveFilesFrom())

	require.NoError(t, f.AddFile("file"))

	assert.Equal(t, true, f.HaveFilesFrom())
}

func TestNewFilterMakeListR(t *testing.T) {
	f, err := NewFilter(nil)
	require.NoError(t, err)

	// Check error if no files
	listR := f.MakeListR(nil)
	err = listR("", nil)
	assert.EqualError(t, err, errFilesFromNotSet.Error())

	// Add some files
	for _, path := range []string{
		"path/to/dir/file1.png",
		"/path/to/dir/file2.png",
		"/path/to/file3.png",
		"/path/to/dir2/file4.png",
		"notfound",
	} {
		err = f.AddFile(path)
		require.NoError(t, err)
	}

	assert.Equal(t, 5, len(f.files))

	// NewObject function for MakeListR
	newObjects := FilesMap{}
	NewObject := func(remote string) (fs.Object, error) {
		if remote == "notfound" {
			return nil, fs.ErrorObjectNotFound
		} else if remote == "error" {
			return nil, assert.AnError
		}
		newObjects[remote] = struct{}{}
		return mockobject.New(remote), nil

	}

	// Callback for ListRFn
	listRObjects := FilesMap{}
	listRcallback := func(entries fs.DirEntries) error {
		for _, entry := range entries {
			listRObjects[entry.Remote()] = struct{}{}
		}
		return nil
	}

	// Make the listR and call it
	listR = f.MakeListR(NewObject)
	err = listR("", listRcallback)
	require.NoError(t, err)

	// Check that the correct objects were created and listed
	want := FilesMap{
		"path/to/dir/file1.png":  {},
		"path/to/dir/file2.png":  {},
		"path/to/file3.png":      {},
		"path/to/dir2/file4.png": {},
	}
	assert.Equal(t, want, newObjects)
	assert.Equal(t, want, listRObjects)

	// Now check an error is returned from NewObject
	require.NoError(t, f.AddFile("error"))
	err = listR("", listRcallback)
	require.EqualError(t, err, assert.AnError.Error())
}

func TestNewFilterMinSize(t *testing.T) {
	f, err := NewFilter(nil)
	require.NoError(t, err)
	f.Opt.MinSize = 100
	testInclude(t, f, []includeTest{
		{"file1.jpg", 100, 0, true},
		{"file2.jpg", 101, 0, true},
		{"potato/file2.jpg", 99, 0, false},
	})
	assert.False(t, f.InActive())
}

func TestNewFilterMaxSize(t *testing.T) {
	f, err := NewFilter(nil)
	require.NoError(t, err)
	f.Opt.MaxSize = 100
	testInclude(t, f, []includeTest{
		{"file1.jpg", 100, 0, true},
		{"file2.jpg", 101, 0, false},
		{"potato/file2.jpg", 99, 0, true},
	})
	assert.False(t, f.InActive())
}

func TestNewFilterMinAndMaxAge(t *testing.T) {
	f, err := NewFilter(nil)
	require.NoError(t, err)
	f.ModTimeFrom = time.Unix(1440000002, 0)
	f.ModTimeTo = time.Unix(1440000003, 0)
	testInclude(t, f, []includeTest{
		{"file1.jpg", 100, 1440000000, false},
		{"file2.jpg", 101, 1440000001, false},
		{"file3.jpg", 102, 1440000002, true},
		{"potato/file1.jpg", 98, 1440000003, true},
		{"potato/file2.jpg", 99, 1440000004, false},
	})
	assert.False(t, f.InActive())
}

func TestNewFilterMinAge(t *testing.T) {
	f, err := NewFilter(nil)
	require.NoError(t, err)
	f.ModTimeTo = time.Unix(1440000002, 0)
	testInclude(t, f, []includeTest{
		{"file1.jpg", 100, 1440000000, true},
		{"file2.jpg", 101, 1440000001, true},
		{"file3.jpg", 102, 1440000002, true},
		{"potato/file1.jpg", 98, 1440000003, false},
		{"potato/file2.jpg", 99, 1440000004, false},
	})
	assert.False(t, f.InActive())
}

func TestNewFilterMaxAge(t *testing.T) {
	f, err := NewFilter(nil)
	require.NoError(t, err)
	f.ModTimeFrom = time.Unix(1440000002, 0)
	testInclude(t, f, []includeTest{
		{"file1.jpg", 100, 1440000000, false},
		{"file2.jpg", 101, 1440000001, false},
		{"file3.jpg", 102, 1440000002, true},
		{"potato/file1.jpg", 98, 1440000003, true},
		{"potato/file2.jpg", 99, 1440000004, true},
	})
	assert.False(t, f.InActive())
}

func TestNewFilterMatches(t *testing.T) {
	f, err := NewFilter(nil)
	require.NoError(t, err)
	add := func(s string) {
		err := f.AddRule(s)
		require.NoError(t, err)
	}
	add("+ cleared")
	add("!")
	add("- /file1.jpg")
	add("+ /file2.png")
	add("+ /*.jpg")
	add("- /*.png")
	add("- /potato")
	add("+ /sausage1")
	add("+ /sausage2*")
	add("+ /sausage3**")
	add("+ /a/*.jpg")
	add("- *")
	testInclude(t, f, []includeTest{
		{"cleared", 100, 0, false},
		{"file1.jpg", 100, 0, false},
		{"file2.png", 100, 0, true},
		{"FILE2.png", 100, 0, false},
		{"afile2.png", 100, 0, false},
		{"file3.jpg", 101, 0, true},
		{"file4.png", 101, 0, false},
		{"potato", 101, 0, false},
		{"sausage1", 101, 0, true},
		{"sausage1/potato", 101, 0, false},
		{"sausage2potato", 101, 0, true},
		{"sausage2/potato", 101, 0, false},
		{"sausage3/potato", 101, 0, true},
		{"a/one.jpg", 101, 0, true},
		{"a/one.png", 101, 0, false},
		{"unicorn", 99, 0, false},
	})
	testDirInclude(t, f, []includeDirTest{
		{"sausage1", false},
		{"sausage2", false},
		{"sausage2/sub", false},
		{"sausage2/sub/dir", false},
		{"sausage3", true},
		{"SAUSAGE3", false},
		{"sausage3/sub", true},
		{"sausage3/sub/dir", true},
		{"sausage4", false},
		{"a", true},
	})
	assert.False(t, f.InActive())
}

func TestNewFilterMatchesIgnoreCase(t *testing.T) {
	f, err := NewFilter(nil)
	require.NoError(t, err)
	f.Opt.IgnoreCase = true
	add := func(s string) {
		err := f.AddRule(s)
		require.NoError(t, err)
	}
	add("+ /file2.png")
	add("+ /sausage3**")
	add("- *")
	testInclude(t, f, []includeTest{
		{"file2.png", 100, 0, true},
		{"FILE2.png", 100, 0, true},
	})
	testDirInclude(t, f, []includeDirTest{
		{"sausage3", true},
		{"SAUSAGE3", true},
	})
	assert.False(t, f.InActive())
}

func TestFilterAddDirRuleOrFileRule(t *testing.T) {
	for _, test := range []struct {
		included bool
		glob     string
		want     string
	}{
		{
			false,
			"potato",
			`--- File filter rules ---
- (^|/)potato$
--- Directory filter rules ---`,
		},
		{
			true,
			"potato",
			`--- File filter rules ---
+ (^|/)potato$
--- Directory filter rules ---
+ ^.*$`,
		},
		{
			false,
			"*",
			`--- File filter rules ---
- (^|/)[^/]*$
--- Directory filter rules ---
- ^.*$`,
		},
		{
			true,
			"*",
			`--- File filter rules ---
+ (^|/)[^/]*$
--- Directory filter rules ---
+ ^.*$`,
		},
		{
			false,
			".*{,/**}",
			`--- File filter rules ---
- (^|/)\.[^/]*(|/.*)$
--- Directory filter rules ---
- (^|/)\.[^/]*(|/.*)$`,
		},
		{
			true,
			"a/b/c/d",
			`--- File filter rules ---
+ (^|/)a/b/c/d$
--- Directory filter rules ---
+ (^|/)a/b/c/$
+ (^|/)a/b/$
+ (^|/)a/$`,
		},
	} {
		f, err := NewFilter(nil)
		require.NoError(t, err)
		err = f.Add(test.included, test.glob)
		require.NoError(t, err)
		got := f.DumpFilters()
		assert.Equal(t, test.want, got, fmt.Sprintf("Add(%v, %q)", test.included, test.glob))
	}
}

func TestFilterForEachLine(t *testing.T) {
	file := testFile(t, `; comment
one
# another comment


two
 # indented comment
three  
four    
five
  six  `)
	defer func() {
		err := os.Remove(file)
		require.NoError(t, err)
	}()
	lines := []string{}
	err := forEachLine(file, func(s string) error {
		lines = append(lines, s)
		return nil
	})
	require.NoError(t, err)
	assert.Equal(t, "one,two,three,four,five,six", strings.Join(lines, ","))
}

func TestFilterMatchesFromDocs(t *testing.T) {
	for _, test := range []struct {
		glob       string
		included   bool
		file       string
		ignoreCase bool
	}{
		{"file.jpg", true, "file.jpg", false},
		{"file.jpg", true, "directory/file.jpg", false},
		{"file.jpg", false, "afile.jpg", false},
		{"file.jpg", false, "directory/afile.jpg", false},
		{"/file.jpg", true, "file.jpg", false},
		{"/file.jpg", false, "afile.jpg", false},
		{"/file.jpg", false, "directory/file.jpg", false},
		{"*.jpg", true, "file.jpg", false},
		{"*.jpg", true, "directory/file.jpg", false},
		{"*.jpg", false, "file.jpg/anotherfile.png", false},
		{"dir/**", true, "dir/file.jpg", false},
		{"dir/**", true, "dir/dir1/dir2/file.jpg", false},
		{"dir/**", false, "directory/file.jpg", false},
		{"dir/**", false, "adir/file.jpg", false},
		{"l?ss", true, "less", false},
		{"l?ss", true, "lass", false},
		{"l?ss", false, "floss", false},
		{"h[ae]llo", true, "hello", false},
		{"h[ae]llo", true, "hallo", false},
		{"h[ae]llo", false, "hullo", false},
		{"{one,two}_potato", true, "one_potato", false},
		{"{one,two}_potato", true, "two_potato", false},
		{"{one,two}_potato", false, "three_potato", false},
		{"{one,two}_potato", false, "_potato", false},
		{"\\*.jpg", true, "*.jpg", false},
		{"\\\\.jpg", true, "\\.jpg", false},
		{"\\[one\\].jpg", true, "[one].jpg", false},
		{"potato", true, "potato", false},
		{"potato", false, "POTATO", false},
		{"potato", true, "potato", true},
		{"potato", true, "POTATO", true},
	} {
		f, err := NewFilter(nil)
		require.NoError(t, err)
		if test.ignoreCase {
			f.Opt.IgnoreCase = true
		}
		err = f.Add(true, test.glob)
		require.NoError(t, err)
		err = f.Add(false, "*")
		require.NoError(t, err)
		included := f.Include(test.file, 0, time.Unix(0, 0))
		if included != test.included {
			t.Errorf("%q match %q: want %v got %v", test.glob, test.file, test.included, included)
		}
	}
}
