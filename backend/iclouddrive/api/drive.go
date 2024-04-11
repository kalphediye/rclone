package api

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/rclone/rclone/fs"
	"github.com/rclone/rclone/lib/rest"
)

//"context"
//"fmt"

//"github.com/rclone/rclone/fs/config/configmap"

const (
	defaultZone        = "com.apple.CloudDocs"
	statusOk           = "OK"
	statusEtagConflict = "ETAG_CONFLICT"
)

type DriveService struct {
	icloud       *Client
	RootID       string
	endpoint     string
	docsEndpoint string

	// lock *sync.Mutex
} //

func NewDriveService(icloud *Client) (*DriveService, error) {
	return &DriveService{icloud: icloud, RootID: "FOLDER::com.apple.CloudDocs::root", endpoint: icloud.Session.AccountInfo.Webservices["drivews"].URL, docsEndpoint: icloud.Session.AccountInfo.Webservices["docws"].URL}, nil
}

func (d *DriveService) GetItemByDriveID(ctx context.Context, id string, include_children bool) (*DriveItem, *http.Response, error) {
	items, resp, err := d.GetItemsByDriveID(ctx, []string{id}, include_children)
	if err != nil {
		return nil, resp, err
	}
	return items[0], resp, err
}

func (d *DriveService) GetItemsByDriveID(ctx context.Context, ids []string, include_children bool) ([]*DriveItem, *http.Response, error) {
	_items := []map[string]any{}
	for _, id := range ids {
		_items = append(_items, map[string]any{
			"drivewsid":        id,
			"partialData":      false,
			"includeHierarchy": false,
		})
	}

	var body *bytes.Reader
	var path string
	if !include_children {
		values := []map[string]any{{
			"items": _items,
		}}
		body, _ = IntoReader(values)
		path = "/retrieveItemDetails"
	} else {
		values := _items
		body, _ = IntoReader(values)
		path = "/retrieveItemDetailsInFolders"
	}

	// body, _ := IntoReader(values)
	opts := rest.Opts{
		Method:       "POST",
		Path:         path,
		ExtraHeaders: d.icloud.Session.GetHeaders(map[string]string{}),
		RootURL:      d.endpoint,
		Body:         body,
	}
	var items []*DriveItem
	resp, err := d.icloud.Session.Request(ctx, opts, nil, &items)
	if err != nil {
		return nil, resp, err
	}

	if items[0].Status != statusOk {
		return nil, resp, fmt.Errorf("%s %s failed, status %s", opts.Method, resp.Request.URL, items[0].Status)
	}

	return items, resp, err
}

func (d *DriveService) GetDocByPath(ctx context.Context, path string) (*Document, *http.Response, error) {
	values := url.Values{}
	values.Set("unified_format", "false")

	body, _ := IntoReader(path)

	opts := rest.Opts{
		Method:       "POST",
		Path:         "/ws/" + defaultZone + "/list/lookup_by_path",
		ExtraHeaders: d.icloud.Session.GetHeaders(map[string]string{}),
		RootURL:      d.docsEndpoint,
		Parameters:   values,
		Body:         body,
	}
	var item []*Document
	resp, err := d.icloud.Session.Request(ctx, opts, nil, &item)
	if err != nil {
		return nil, resp, err
	}

	return item[0], resp, err
}

func (d *DriveService) GetItemByPath(ctx context.Context, path string) (*DriveItem, *http.Response, error) {
	values := url.Values{}
	values.Set("unified_format", "true")

	body, _ := IntoReader(path)

	opts := rest.Opts{
		Method:       "POST",
		Path:         "/ws/" + defaultZone + "/list/lookup_by_path",
		ExtraHeaders: d.icloud.Session.GetHeaders(map[string]string{}),
		RootURL:      d.docsEndpoint,
		Parameters:   values,
		Body:         body,
	}
	var item []*DriveItem
	resp, err := d.icloud.Session.Request(ctx, opts, nil, &item)
	if err != nil {
		return nil, resp, err
	}

	return item[0], resp, err
}

func (d *DriveService) GetDocByItemID(ctx context.Context, id string) (*Document, *http.Response, error) {
	values := url.Values{}
	values.Set("document_id", id)
	values.Set("unified_format", "false") // important
	opts := rest.Opts{
		Method:       "GET",
		Path:         "/ws/" + defaultZone + "/list/lookup_by_id",
		ExtraHeaders: d.icloud.Session.GetHeaders(map[string]string{}),
		RootURL:      d.docsEndpoint,
		Parameters:   values,
	}
	var item *Document
	resp, err := d.icloud.Session.Request(ctx, opts, nil, &item)
	if err != nil {
		return nil, resp, err
	}

	return item, resp, err
}

func (d *DriveService) DownloadFile(ctx context.Context, id string, opt []fs.OpenOption) (*http.Response, error) {
	_, zone, docid := DeconstructDriveID(id)
	values := url.Values{}
	values.Set("document_id", docid)

	opts := &rest.Opts{
		Method:       "GET",
		Path:         "/ws/" + zone + "/download/by_id",
		Parameters:   values,
		ExtraHeaders: d.icloud.Session.GetHeaders(map[string]string{}),
		RootURL:      d.docsEndpoint,
	}

	var filer *FileRequest
	resp, err := d.icloud.srv.CallJSON(ctx, opts, nil, &filer)

	var url string
	if filer.DataToken != nil {
		url = filer.DataToken.URL
	} else {
		url = filer.PackageToken.URL
	}

	// todo we should add chunk support
	if err == nil {
		opts := &rest.Opts{
			Method:       "GET",
			ExtraHeaders: d.icloud.Session.GetHeaders(map[string]string{}),
			RootURL:      url,
			Options:      opt,
		}
		return d.icloud.srv.Call(ctx, opts)
	}

	return resp, err
}

func (d *DriveService) MoveItemToTrashByID(ctx context.Context, drivewsid, etag string, force bool) (*DriveItem, *http.Response, error) {
	values := map[string]any{
		"items": []map[string]any{{
			"drivewsid": drivewsid,
			"etag":      etag,
			"clientId":  drivewsid,
		}}}

	body, _ := IntoReader(values)
	opts := rest.Opts{
		Method:       "POST",
		Path:         "/moveItemsToTrash",
		ExtraHeaders: d.icloud.Session.GetHeaders(map[string]string{}),
		RootURL:      d.endpoint,
		Body:         body,
	}

	item := struct {
		Items []*DriveItem `json:"items"`
	}{}
	resp, err := d.icloud.Session.Request(ctx, opts, nil, &item)

	if err != nil {
		return nil, resp, err
	}

	if item.Items[0].Status != statusOk {
		// rerun with latest etag
		if force && item.Items[0].Status == "ETAG_CONFLICT" {
			return d.MoveItemToTrashByID(ctx, drivewsid, item.Items[0].Etag, false)
		}

		return nil, resp, fmt.Errorf("%s %s failed, status %s", opts.Method, resp.Request.URL, item.Items[0].Status)
	}

	return item.Items[0], resp, err
}

// func (d *DriveService) EmptyTrash(ctx context.Context, drivewsid, etag string, force bool) (*DriveItem, *http.Response, error) {
// 	values := map[string]any{
// 		"items": []map[string]any{{
// 			"drivewsid": drivewsid,
// 			"etag":      etag,
// 			"clientId":  drivewsid,
// 		}}}

// 	body, _ := IntoReader(values)
// 	opts := rest.Opts{
// 		Method:       "POST",
// 		Path:         "/moveItemsToTrash",
// 		ExtraHeaders: d.icloud.Session.GetHeaders(map[string]string{}),
// 		RootURL:      d.endpoint,
// 		Body:         body,
// 	}

// 	item := struct {
// 		Items []*DriveItem `json:"items"`
// 	}{}
// 	resp, err := d.icloud.Session.Request(ctx, opts, nil, &item)

// 	if err != nil {
// 		return nil, resp, err
// 	}

// 	if item.Items[0].Status != statusOk {
// 		// rerun with latest etag
// 		if force && item.Items[0].Status == "ETAG_CONFLICT" {
// 			return d.MoveItemToTrashByID(ctx, drivewsid, item.Items[0].Etag, false)
// 		}

// 		return nil, resp, fmt.Errorf("%s %s failed, status %s", opts.Method, resp.Request.URL, item.Items[0].Status)
// 	}

// 	return item.Items[0], resp, err
// }

func (d *DriveService) CreateNewFolderByID(ctx context.Context, drivewsid, name string) (*DriveItem, *http.Response, error) {
	values := map[string]any{
		"destinationDrivewsId": drivewsid,
		"folders": []map[string]any{{
			"clientId": "FOLDER::UNKNOWN_ZONE::TempId-" + uuid.New().String(),
			"name":     name,
		}},
	}

	body, _ := IntoReader(values)
	opts := rest.Opts{
		Method:       "POST",
		Path:         "/createFolders",
		ExtraHeaders: d.icloud.Session.GetHeaders(map[string]string{}),
		RootURL:      d.endpoint,
		Body:         body,
	}
	var fResp *CreateFoldersResponse
	resp, err := d.icloud.Session.Request(ctx, opts, nil, &fResp)

	status := fResp.Folders[0].Status
	if status != statusOk {
		return nil, resp, fmt.Errorf("%s %s failed, status %s", opts.Method, resp.Request.URL, status)
	}

	return fResp.Folders[0], resp, err
}

func (d *DriveService) RenameItemByID(ctx context.Context, drivewsid, etag, name string, force bool) (*DriveItem, *http.Response, error) {
	// split := strings.Split(name, ".")
	values := map[string]any{
		"items": []map[string]any{{
			"drivewsid": drivewsid,
			"name":      name,
			"etag":      etag,
			// "extension": split[1],
		}},
	}

	//{"items":[{"drivewsid":"FILE::com.apple.CloudDocs::6F246527-504C-4073-BAF2-26C6DECE6CC0","etag":"3ne::3nd","name":"notes.staan","extension":"partial"}]}

	body, _ := IntoReader(values)
	opts := rest.Opts{
		Method:       "POST",
		Path:         "/renameItems",
		ExtraHeaders: d.icloud.Session.GetHeaders(map[string]string{}),
		RootURL:      d.endpoint,
		Body:         body,
	}
	var items *DriveItem
	resp, err := d.icloud.Session.Request(ctx, opts, nil, &items)

	if err != nil {
		return nil, resp, err
	}

	status := items.Items[0].Status
	if status != statusOk {
		// rerun with latest etag
		if force && status == "ETAG_CONFLICT" {
			return d.RenameItemByID(ctx, drivewsid, items.Items[0].Etag, name, false)
		}

		err = fmt.Errorf("%s %s failed, status %s", opts.Method, resp.Request.URL, status)
	}

	return items.Items[0], resp, err
}

func (d *DriveService) MoveItemByID(ctx context.Context, drivewsid, etag, dstDrivewsid string, force bool) (*DriveItem, *http.Response, error) {
	values := map[string]any{
		"destinationDrivewsId": dstDrivewsid,
		"items": []map[string]any{{
			"drivewsid": drivewsid,
			"etag":      etag,
			"clientId":  drivewsid,
		}},
	}

	body, _ := IntoReader(values)
	opts := rest.Opts{
		Method:       "POST",
		Path:         "/moveItems",
		ExtraHeaders: d.icloud.Session.GetHeaders(map[string]string{}),
		RootURL:      d.endpoint,
		Body:         body,
	}

	var items *DriveItem
	resp, err := d.icloud.Session.Request(ctx, opts, nil, &items)

	if err != nil {
		return nil, resp, err
	}

	status := items.Items[0].Status
	if status != statusOk {
		// rerun with latest etag
		if force && status == "ETAG_CONFLICT" {
			return d.MoveItemByID(ctx, drivewsid, items.Items[0].Etag, dstDrivewsid, false)
		}

		err = fmt.Errorf("%s %s failed, status %s", opts.Method, resp.Request.URL, status)
	}

	return items.Items[0], resp, err
}

// type CopyResponse struct {
// 	ItemID   string     `json:"item_id"`
// 	ItemInfo *DriveItem `json:"item_info"`
// }

// func (d *DriveService) DeleteItemsByID(ctx context.Context, []map[]drivewsid, etag) (*http.Response, error) {
// 	values := map[string]any{
// 		"destinationDrivewsId": dstDrivewsid,
// 		"items": []map[string]any{{
// 			"drivewsid": drivewsid,
// 			"etag":      etag,
// 			"clientId":  drivewsid,
// 		}},
// 	}

// 	body, _ := IntoReader(values)
// 	opts := rest.Opts{
// 		Method:       "POST",
// 		Path:         "/moveItems",
// 		ExtraHeaders: d.icloud.Session.GetHeaders(map[string]string{}),
// 		RootURL:      d.endpoint,
// 		Body:         body,
// 	}

// 	resp, err := d.icloud.Session.Request(ctx, opts, nil, nil)

// 	return resp, err
// }

func (d *DriveService) CopyDocByItemID(ctx context.Context, itemId string) (*CopyResponse, *http.Response, error) {
	// putting name in info doesnt work. extension does work so assume this is a bug in the endpoint
	values := map[string]any{
		"info_to_update": map[string]any{},
	}

	body, _ := IntoReader(values)

	opts := rest.Opts{
		Method:       "POST",
		Path:         "/v1/item/copy/" + itemId,
		ExtraHeaders: d.icloud.Session.GetHeaders(map[string]string{}),
		RootURL:      d.docsEndpoint,
		Body:         body,
	}

	var info *CopyResponse
	resp, err := d.icloud.Session.Request(ctx, opts, nil, &info)
	if err != nil {
		return nil, resp, err
	}
	return info, resp, err
}

func (d *DriveService) UploadFile(ctx context.Context, in io.Reader, size int64, name, folderID string, mTime time.Time) (*DriveItem, *http.Response, error) {
	// detect MIME type by looking at the filename only
	mimeType := mime.TypeByExtension(filepath.Ext(name))
	if mimeType == "" {
		// api requires a mime type passed in
		mimeType = "text/plain"
	}

	values := map[string]any{
		"filename":     name,
		"type":         "FILE",
		"size":         strconv.FormatInt(size, 10),
		"content_type": strings.Split(mimeType, ";")[0],
	}
	body, _ := IntoReader(values)
	opts := rest.Opts{
		Method:       "POST",
		Path:         "/ws/" + defaultZone + "/upload/web",
		ExtraHeaders: d.icloud.Session.GetHeaders(map[string]string{}),
		RootURL:      d.docsEndpoint,
		Body:         body,
	}
	var responseInfo []*UploadResponse
	resp, err := d.icloud.srv.CallJSON(ctx, &opts, nil, &responseInfo)
	if err != nil {
		return nil, resp, err
	}

	// TODO: implement multipart upload
	opts = rest.Opts{
		Method:        "POST",
		ExtraHeaders:  d.icloud.Session.GetHeaders(map[string]string{}),
		RootURL:       responseInfo[0].URL,
		Body:          in,
		ContentLength: &size,
		ContentType:   mimeType,
		// MultipartContentName: "files",
		MultipartFileName: name,
	}
	var singleFileResponse *SingleFileResponse
	resp, err = d.icloud.srv.CallJSON(ctx, &opts, nil, &singleFileResponse)
	if err != nil {
		return nil, resp, err
	}
	_, _, StartingDocumentID := DeconstructDriveID(folderID)
	r := NewUpdateFileInfo()
	r.DocumentID = responseInfo[0].DocumentId
	r.Path.Path = name
	r.Path.StartingDocumentID = StartingDocumentID
	r.Data.Receipt = singleFileResponse.SingleFile.Receipt
	r.Data.Signature = singleFileResponse.SingleFile.Signature
	r.Data.ReferenceSignature = singleFileResponse.SingleFile.ReferenceSignature
	r.Data.WrappingKey = singleFileResponse.SingleFile.WrappingKey
	r.Data.Size = singleFileResponse.SingleFile.Size
	r.Mtime = mTime.Unix() * 1000
	r.Btime = mTime.Unix() * 1000

	return d.UpdateFile(ctx, &r)
	// return d.UpdateFile(ctx, responseInfo[0].DocumentId, name, folderID, mTime, singleFileResponse.SingleFile)
}

func (d *DriveService) UpdateFile(ctx context.Context, r *UpdateFileInfo) (*DriveItem, *http.Response, error) {

	// func (d *DriveService) UpdateFile(ctx context.Context, documentID, name, folderID string, mTime time.Time, singleFile *SingleFileInfo) (*DriveItem, *http.Response, error) {
	// _, _, starting_document_id := DeconstructId(folderID)
	// _, _, documentId = DeconstructId(documentId)

	// values := map[string]any{
	// 	"command":           "add_file",
	// 	"create_short_guid": true,
	// 	"document_id":       documentID,
	// 	"path": map[string]any{
	// 		"starting_document_id": starting_document_id,
	// 		"path":                 name,
	// 	},
	// 	"allow_conflict": true,
	// 	"file_flags": map[string]any{
	// 		"is_writable":   true,
	// 		"is_executable": false,
	// 		"is_hidden":     false,
	// 	},
	// 	"mtime": mTime.Unix() * 1000,
	// 	"btime": mTime.Unix() * 1000,
	// }
	// if singleFile != nil {
	// 	values["data"] = map[string]any{
	// 		"signature":           singleFile.Signature,
	// 		"wrapping_key":        singleFile.WrappingKey,
	// 		"reference_signature": singleFile.ReferenceSignature,
	// 		"size":                singleFile.Size,
	// 		"receipt":             singleFile.Receipt,
	// 	}
	// }

	body, _ := IntoReader(r)
	opts := rest.Opts{
		Method:       "POST",
		Path:         "/ws/" + defaultZone + "/update/documents",
		ExtraHeaders: d.icloud.Session.GetHeaders(map[string]string{}),
		RootURL:      d.docsEndpoint,
		Body:         body,
	}
	var responseInfo *DocumentUpdateResponse
	resp, err := d.icloud.srv.CallJSON(ctx, &opts, nil, &responseInfo)
	if err != nil {
		return nil, resp, err
	}

	doc := responseInfo.Results[0].Document
	item := DriveItem{
		Drivewsid:    "FILE::com.apple.CloudDocs::" + doc.DocumentID,
		Docwsid:      doc.DocumentID,
		Itemid:       doc.ItemID,
		Etag:         doc.Etag,
		ParentID:     doc.ParentID,
		DateModified: time.Unix(r.Mtime, 0),
		DateCreated:  time.Unix(r.Mtime, 0),
		Type:         doc.Type,
		Name:         doc.Name,
		Size:         doc.Size,
	}
	// driveId := "FILE::com.apple.CloudDocs::" + responseInfo.Results[0].Document.DocumentID
	return &item, resp, err
}

// async getNode(nodeId: {drivewsid: string} | string = "FOLDER::com.apple.CloudDocs::root") {
// 	return new iCloudDriveNode(this,
// 		typeof nodeId === "string" ? nodeId : nodeId.drivewsid
// 	).refresh();
// }

type UpdateFileInfo struct {
	AllowConflict   bool   `json:"allow_conflict"`
	Btime           int64  `json:"btime"`
	Command         string `json:"command"`
	CreateShortGUID bool   `json:"create_short_guid"`
	Data            struct {
		Receipt            string `json:"receipt,omitempty"`
		ReferenceSignature string `json:"reference_signature,omitempty"`
		Signature          string `json:"signature,omitempty"`
		Size               int    `json:"size,omitempty"`
		WrappingKey        string `json:"wrapping_key,omitempty"`
	} `json:"data,omitempty"`
	DocumentID string    `json:"document_id"`
	FileFlags  FileFlags `json:"file_flags"`
	Mtime      int64     `json:"mtime"`
	Path       struct {
		Path               string `json:"path"`
		StartingDocumentID string `json:"starting_document_id"`
	} `json:"path"`
}

type FileFlags struct {
	IsExecutable bool `json:"is_executable"`
	IsHidden     bool `json:"is_hidden"`
	IsWritable   bool `json:"is_writable"`
}

func NewUpdateFileInfo() UpdateFileInfo {
	return UpdateFileInfo{
		Command:         "add_file",
		CreateShortGUID: true,
		AllowConflict:   true,
		FileFlags: FileFlags{
			IsExecutable: true,
			IsHidden:     false,
			IsWritable:   false,
		},
	}
}

// 	"command":           "add_file",
// 	"create_short_guid": true,
// 	"document_id":       documentID,
// 	"path": map[string]any{
// 		"starting_document_id": starting_document_id,
// 		"path":                 name,
// 	},
// 	"allow_conflict": true,
// 	"file_flags": map[string]any{
// 		"is_writable":   true,
// 		"is_executable": false,
// 		"is_hidden":     false,
// 	},
// 	"mtime": mTime.Unix() * 1000,
// 	"btime": mTime.Unix() * 1000,
// }
// if singleFile != nil {
// 	values["data"] = map[string]any{
// 		"signature":           singleFile.Signature,
// 		"wrapping_key":        singleFile.WrappingKey,
// 		"reference_signature": singleFile.ReferenceSignature,
// 		"size":                singleFile.Size,
// 		"receipt":             singleFile.Receipt,
// 	}

type CopyResponse struct {
	ItemID   string `json:"item_id"`
	ItemInfo struct {
		Name       string `json:"name"`
		ModifiedAt string `json:"modified_at"`
	} `json:"item_info"`
}

type DocumentUpdateResponse struct {
	Status struct {
		StatusCode   int    `json:"status_code"`
		ErrorMessage string `json:"error_message"`
	} `json:"status"`
	Results []struct {
		Status struct {
			StatusCode   int    `json:"status_code"`
			ErrorMessage string `json:"error_message"`
		} `json:"status"`
		OperationID interface{} `json:"operation_id"`
		Document    *Document   `json:"document"`
	} `json:"results"`
}

type Document struct {
	Status struct {
		StatusCode   int    `json:"status_code"`
		ErrorMessage string `json:"error_message"`
	} `json:"status"`
	DocumentID string `json:"document_id"`
	ItemID     string `json:"item_id"`
	Urls       struct {
		URLDownload string `json:"url_download"`
	} `json:"urls"`
	Etag           string       `json:"etag"`
	ParentID       string       `json:"parent_id"`
	Name           string       `json:"name"`
	Type           string       `json:"type"`
	Deleted        bool         `json:"deleted"`
	Mtime          int64        `json:"mtime"`
	LastEditorName string       `json:"last_editor_name"`
	Data           DocumentData `json:"data"`
	Size           int64        `json:"size"`
	Btime          int64        `json:"btime"`
	Zone           string       `json:"zone"`
	FileFlags      struct {
		IsExecutable bool `json:"is_executable"`
		IsWritable   bool `json:"is_writable"`
		IsHidden     bool `json:"is_hidden"`
	} `json:"file_flags"`
	LastOpenedTime   int64       `json:"lastOpenedTime"`
	RestorePath      interface{} `json:"restorePath"`
	HasChainedParent bool        `json:"hasChainedParent"`
}

type DocumentData struct {
	Signature          string `json:"signature"`
	Owner              string `json:"owner"`
	Size               int    `json:"size"`
	ReferenceSignature string `json:"reference_signature"`
	WrappingKey        string `json:"wrapping_key"`
	PcsInfo            string `json:"pcsInfo"`
}

type SingleFileResponse struct {
	SingleFile *SingleFileInfo `json:"singleFile"`
}

type SingleFileInfo struct {
	ReferenceSignature string `json:"referenceChecksum"`
	Size               int    `json:"size"`
	Signature          string `json:"fileChecksum"`
	WrappingKey        string `json:"wrappingKey"`
	Receipt            string `json:"receipt"`
}

type UploadResponse struct {
	URL        string `json:"url"`
	DocumentId string `json:"document_id"`
}

type FileRequestToken struct {
	URL                string `json:"url"`
	Token              string `json:"token"`
	Signature          string `json:"signature"`
	WrappingKey        string `json:"wrapping_key"`
	ReferenceSignature string `json:"reference_signature"`
}

type FileRequest struct {
	DocumentID   string            `json:"document_id"`
	ItemID       string            `json:"item_id"`
	OwnerDsid    int64             `json:"owner_dsid"`
	DataToken    *FileRequestToken `json:"data_token,omitempty"`
	PackageToken *FileRequestToken `json:"package_token,omitempty"`
	DoubleEtag   string            `json:"double_etag"`
}

type CreateFoldersResponse struct {
	Folders []*DriveItem `json:"folders"`
}

type DriveItem struct {
	DateCreated         time.Time    `json:"dateCreated"`
	Drivewsid           string       `json:"drivewsid"`
	Docwsid             string       `json:"docwsid"`
	Itemid              string       `json:"item_id"`
	Zone                string       `json:"zone"`
	Name                string       `json:"name"`
	ParentID            string       `json:"parentId"`
	Hierarchy           []DriveItem  `json:"hierarchy"`
	Etag                string       `json:"etag"`
	Type                string       `json:"type"`
	AssetQuota          int64        `json:"assetQuota"`
	FileCount           int64        `json:"fileCount"`
	ShareCount          int64        `json:"shareCount"`
	ShareAliasCount     int64        `json:"shareAliasCount"`
	DirectChildrenCount int64        `json:"directChildrenCount"`
	Items               []*DriveItem `json:"items"`
	NumberOfItems       int64        `json:"numberOfItems"`
	Status              string       `json:"status"`
	Extension           string       `json:"extension,omitempty"`
	DateModified        time.Time    `json:"dateModified,omitempty"`
	DateChanged         time.Time    `json:"dateChanged,omitempty"`
	Size                int64        `json:"size,omitempty"`
	LastOpenTime        time.Time    `json:"lastOpenTime,omitempty"`
	Urls                struct {
		URLDownload string `json:"url_download"`
	} `json:"urls"`
}

func (d *DriveItem) IsFolder() bool {
	return d.Type == "FOLDER"
}

// name + extension
func (d *DriveItem) FullName() string {
	if d.Extension != "" {
		return d.Name + "." + d.Extension
	}
	return d.Name
}

func GetDriveIDFromDocID(id string) string {
	return "FILE::" + defaultZone + "::" + id
}

func GetDocIDFromDriveID(id string) string {
	split := strings.Split(id, "::")
	return split[len(split)-1]
}

func DeconstructDriveID(id string) (docType, zone, docid string) {
	split := strings.Split(id, "::")
	return split[0], split[1], split[2]
}
