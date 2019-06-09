package api

import (
	"fmt"
)

// M1 protocol constants and structures
const (
	APIServerURL      = "https://cloud.mail.ru"
	OAuthURL          = "https://o2.mail.ru/token"
	DispatchServerURL = "https://dispatcher.cloud.mail.ru"
	DefaultUserAgent  = "CloudDiskOWindows 17.12.0009 beta WzBbt1Ygbm"
	OAuthClientID     = "cloud-win"
)

// ServerErrorResponse represents erroneous API response.
type ServerErrorResponse struct {
	Message string `json:"body"`
	Time    int64  `json:"time"`
	Status  int    `json:"status"`
}

func (e *ServerErrorResponse) Error() string {
	return fmt.Sprintf("%s (%d)", e.Message, e.Status)
}

// FileErrorResponse represents erroneous API response for a file
type FileErrorResponse struct {
	Body struct {
		Home struct {
			Value string `json:"value"`
			Error string `json:"error"`
		} `json:"home"`
	} `json:"body"`
	Message string
	Status  int    `json:"status"`
	Account string `json:"email,omitempty"`
	Time    int64  `json:"time,omitempty"`
}

func (e *FileErrorResponse) Error() string {
	return fmt.Sprintf("%s (%d)", e.Message, e.Status)
}

// UserInfoResponse contains account metadata
type UserInfoResponse struct {
	Body struct {
		AccountType     string `json:"account_type"`
		AccountVerified bool   `json:"account_verified"`
		Cloud           struct {
			Beta struct {
				Allowed bool `json:"allowed"`
				Asked   bool `json:"asked"`
			} `json:"beta"`
			Billing struct {
				ActiveCostID string `json:"active_cost_id"`
				ActiveRateID string `json:"active_rate_id"`
				AutoProlong  bool   `json:"auto_prolong"`
				Basequota    int64  `json:"basequota"`
				Enabled      bool   `json:"enabled"`
				Expires      int    `json:"expires"`
				Prolong      bool   `json:"prolong"`
				Promocodes   struct {
				} `json:"promocodes"`
				Subscription []interface{} `json:"subscription"`
				Version      string        `json:"version"`
			} `json:"billing"`
			Bonuses struct {
				CameraUpload bool `json:"camera_upload"`
				Complete     bool `json:"complete"`
				Desktop      bool `json:"desktop"`
				Feedback     bool `json:"feedback"`
				Links        bool `json:"links"`
				Mobile       bool `json:"mobile"`
				Registration bool `json:"registration"`
			} `json:"bonuses"`
			Enable struct {
				Sharing bool `json:"sharing"`
			} `json:"enable"`
			FileSizeLimit int64 `json:"file_size_limit"`
			Space         struct {
				BytesTotal int64 `json:"bytes_total"`
				BytesUsed  int   `json:"bytes_used"`
				Overquota  bool  `json:"overquota"`
			} `json:"space"`
		} `json:"cloud"`
		Cloudflags struct {
			Exists bool `json:"exists"`
		} `json:"cloudflags"`
		Domain string `json:"domain"`
		Login  string `json:"login"`
		Newbie bool   `json:"newbie"`
		UI     struct {
			ExpandLoader bool   `json:"expand_loader"`
			Kind         string `json:"kind"`
			Sidebar      bool   `json:"sidebar"`
			Sort         struct {
				Order string `json:"order"`
				Type  string `json:"type"`
			} `json:"sort"`
			Thumbs bool `json:"thumbs"`
		} `json:"ui"`
	} `json:"body"`
	Email  string `json:"email"`
	Status int    `json:"status"`
	Time   int64  `json:"time"`
}

// ListItem ...
type ListItem struct {
	Count struct {
		Folders int `json:"folders"`
		Files   int `json:"files"`
	} `json:"count,omitempty"`
	Kind      string `json:"kind"`
	Type      string `json:"type"`
	Name      string `json:"name"`
	Home      string `json:"home"`
	Size      int64  `json:"size"`
	Mtime     int64  `json:"mtime,omitempty"`
	Hash      string `json:"hash,omitempty"`
	VirusScan string `json:"virus_scan,omitempty"`
	Tree      string `json:"tree,omitempty"`
	Grev      int    `json:"grev,omitempty"`
	Rev       int    `json:"rev,omitempty"`
}

// ItemInfoResponse ...
type ItemInfoResponse struct {
	Email  string   `json:"email"`
	Body   ListItem `json:"body"`
	Time   int64    `json:"time"`
	Status int      `json:"status"`
}

// FolderInfoResponse ...
type FolderInfoResponse struct {
	Body struct {
		Count struct {
			Folders int `json:"folders"`
			Files   int `json:"files"`
		} `json:"count"`
		Tree string `json:"tree"`
		Name string `json:"name"`
		Grev int    `json:"grev"`
		Size int64  `json:"size"`
		Sort struct {
			Order string `json:"order"`
			Type  string `json:"type"`
		} `json:"sort"`
		Kind string     `json:"kind"`
		Rev  int        `json:"rev"`
		Type string     `json:"type"`
		Home string     `json:"home"`
		List []ListItem `json:"list"`
	} `json:"body,omitempty"`
	Time   int64  `json:"time"`
	Status int    `json:"status"`
	Email  string `json:"email"`
}

// ShardInfoResponse ...
type ShardInfoResponse struct {
	Email string `json:"email"`
	Body  struct {
		Video []struct {
			Count string `json:"count"`
			URL   string `json:"url"`
		} `json:"video"`
		ViewDirect []struct {
			Count string `json:"count"`
			URL   string `json:"url"`
		} `json:"view_direct"`
		WeblinkView []struct {
			Count string `json:"count"`
			URL   string `json:"url"`
		} `json:"weblink_view"`
		WeblinkVideo []struct {
			Count string `json:"count"`
			URL   string `json:"url"`
		} `json:"weblink_video"`
		WeblinkGet []struct {
			Count int    `json:"count"`
			URL   string `json:"url"`
		} `json:"weblink_get"`
		Stock []struct {
			Count string `json:"count"`
			URL   string `json:"url"`
		} `json:"stock"`
		WeblinkThumbnails []struct {
			Count string `json:"count"`
			URL   string `json:"url"`
		} `json:"weblink_thumbnails"`
		PublicUpload []struct {
			Count string `json:"count"`
			URL   string `json:"url"`
		} `json:"public_upload"`
		Auth []struct {
			Count string `json:"count"`
			URL   string `json:"url"`
		} `json:"auth"`
		Web []struct {
			Count string `json:"count"`
			URL   string `json:"url"`
		} `json:"web"`
		View []struct {
			Count string `json:"count"`
			URL   string `json:"url"`
		} `json:"view"`
		Upload []struct {
			Count string `json:"count"`
			URL   string `json:"url"`
		} `json:"upload"`
		Get []struct {
			Count string `json:"count"`
			URL   string `json:"url"`
		} `json:"get"`
		Thumbnails []struct {
			Count string `json:"count"`
			URL   string `json:"url"`
		} `json:"thumbnails"`
	} `json:"body"`
	Time   int64 `json:"time"`
	Status int   `json:"status"`
}

// GenericOperationResponse ...
type GenericOperationResponse struct {
	Email  string `json:"email"`
	Time   int64  `json:"time"`
	Status int    `json:"status"`
	// ignore other fields
}

// CopyResponse ...
type CopyResponse struct {
	Email  string `json:"email"`
	Body   string `json:"body"`
	Time   int64  `json:"time"`
	Status int    `json:"status"`
}
