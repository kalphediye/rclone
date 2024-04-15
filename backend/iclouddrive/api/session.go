package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/google/uuid"
	"github.com/oracle/oci-go-sdk/v65/common"

	//"github.com/rclone/rclone/fs"
	config "github.com/rclone/rclone/fs/config"
	"github.com/rclone/rclone/fs/fshttp"
	"github.com/rclone/rclone/lib/rest"
)

type Session struct {
	SessionToken   string         `json:"session_token"`
	Scnt           string         `json:"scnt"`
	SessionID      string         `json:"session_id"`
	AccountCountry string         `json:"account_country"`
	TrustToken     string         `json:"trust_token"`
	ClientID       string         `json:"client_id"`
	Cookies        []*http.Cookie `json:"cookies"`
	AccountInfo    AccountInfo    `json:"account_info"`

	srv *rest.Client `json:"-"`
}

func (s *Session) String() string {
	jsession, _ := json.Marshal(s)
	return string(jsession)
}

func (s *Session) Set(b []byte) error {
	// var session *Session
	_ = json.Unmarshal(b, &s)
	return nil
	// *s = session
}

// func (s *Session) Scan(sep rune, sc fmt.ScanState, ch rune) error {
// 	token, err := sc.Token(true, func(rune) bool { return true })
// 	if err != nil {
// 		return err
// 	}
// 	return s.Set(bytes.TrimSpace(token))
// }

func (s *Session) GetFileLocation() string {
	return filepath.Dir(config.GetConfigPath()) + "/icloud_session.json"
}

func (s *Session) Save() error {
	_ = os.WriteFile(s.GetFileLocation(), []byte(s.String()), 0644)
	return nil
}

func (s *Session) Load() (*Session, error) {
	jsession, _ := os.ReadFile(s.GetFileLocation())
	_ = s.Set(jsession)
	return s, nil
}

func (s *Session) Request(ctx context.Context, opts rest.Opts, request interface{}, response interface{}) (*http.Response, error) {
	resp, err := s.srv.CallJSON(ctx, &opts, &request, &response)

	if err != nil {
		return resp, fmt.Errorf("%s %s failed, status %d, err: %s", opts.Method, resp.Request.URL, resp.StatusCode, err)
	}

	if val := resp.Header.Get("X-Apple-ID-Account-Country"); val != "" {
		s.AccountCountry = val
	}
	if val := resp.Header.Get("X-Apple-ID-Session-Id"); val != "" {
		s.SessionID = val
	}
	if val := resp.Header.Get("X-Apple-Session-Token"); val != "" {
		s.SessionToken = val
	}
	if val := resp.Header.Get("X-Apple-TwoSV-Trust-Token"); val != "" {
		s.TrustToken = val
	}
	if val := resp.Header.Get("scnt"); val != "" {
		s.Scnt = val

	}

	return resp, nil
}

func (s *Session) Requires2FA() bool {
	return s.AccountInfo.DsInfo.HsaVersion == 2 && s.AccountInfo.HsaChallengeRequired
}

func (s *Session) SignIn(ctx context.Context, appleID, password string) error {
	trustTokens := []string{}
	if s.TrustToken != "" {
		trustTokens = []string{s.TrustToken}
	}
	values := map[string]any{
		"accountName": appleID,
		"password":    password,
		"rememberMe":  true,
		"trustTokens": trustTokens,
	}
	body, _ := IntoReader(values)
	opts := rest.Opts{
		Method:       "POST",
		Path:         "/signin",
		Parameters:   url.Values{},
		ExtraHeaders: s.GetAuthHeaders(map[string]string{}),
		RootURL:      authEndpoint,
		IgnoreStatus: true, // need to handle 409 for hsa2
		NoResponse:   true,
		Body:         body,
	}
	opts.Parameters.Set("isRememberMeEnabled", "true")
	_, err := s.Request(ctx, opts, nil, nil)

	//if (resp.StatusCode < 200 || resp.StatusCode > 299) && resp.StatusCode != 409 {
	//	return err
	//}

	return err

}

func (s *Session) AuthWithToken(ctx context.Context) error {
	//fmt.Printf("%s", srv);

	values := map[string]any{
		"accountCountryCode": s.AccountCountry,
		"dsWebAuthToken":     s.SessionToken,
		"extended_login":     true,
		"trustToken":         s.TrustToken,
	}
	body, _ := IntoReader(values)
	opts := rest.Opts{
		Method:       "POST",
		Path:         "/accountLogin",
		ExtraHeaders: GetCommonHeaders(map[string]string{}),
		RootURL:      setupEndpoint,
		Body:         body,
	}
	// X-APPLE-WEBAUTH-TOKEN
	resp, err := s.Request(ctx, opts, nil, &s.AccountInfo)

	if err == nil {
		s.Cookies = resp.Cookies()
	}

	return err
}

func (s *Session) Validate2FACode(ctx context.Context, code string) error {
	values := map[string]interface{}{"securityCode": map[string]string{"code": code}}
	body, _ := IntoReader(values)

	headers := s.GetAuthHeaders(map[string]string{})
	headers["scnt"] = s.Scnt
	headers["X-Apple-ID-Session-Id"] = s.SessionID

	opts := rest.Opts{
		Method:       "POST",
		Path:         "/verify/trusteddevice/securitycode",
		ExtraHeaders: headers,
		RootURL:      authEndpoint,
		Body:         body,
		NoResponse:   true,
	}
	// _, err := srv.CallJSON(ctx, &opts, nil, &s.AccountInfo)
	_, err := s.Request(ctx, opts, nil, nil)
	if err == nil {
		if err := s.TrustSession(ctx); err != nil {
			return err
		}

		return nil
	}

	return fmt.Errorf("validate2FACode failed: %w", err)
}

func (s *Session) TrustSession(ctx context.Context) error {
	headers := s.GetAuthHeaders(map[string]string{})
	headers["scnt"] = s.Scnt
	headers["X-Apple-ID-Session-Id"] = s.SessionID

	opts := rest.Opts{
		Method:        "GET",
		Path:          "/2sv/trust",
		ExtraHeaders:  headers,
		RootURL:       authEndpoint,
		NoResponse:    true,
		ContentLength: common.Int64(0),
	}

	// _, err := srv.CallJSON(ctx, &opts, nil, &s.AccountInfo)
	_, err := s.Request(ctx, opts, nil, nil)
	if err != nil {
		return fmt.Errorf("trustSession failed: %w", err)
	}
	// cookies := resp.Cookies()
	// srv.SetCookie(cookies...)
	// s.Cookies = cookies

	return s.AuthWithToken(ctx)
}

// func (s *Session) validateToken(ctx context.Context, srv *rest.Client) error {
// 	fmt.Printf("Checking session token validity\n")
// 	headers := GetCommonHeaders(map[string]string{})

// 	opts := rest.Opts{
// 		Method:       "POST",
// 		Path:         "/validate",
// 		ExtraHeaders: headers,
// 		RootURL:      setupEndpoint,
// 	}
// 	_, err := srv.CallJSON(ctx, &opts, nil, &s.AccountInfo)
// 	if err != nil {
// 		return fmt.Errorf("validateToken failed: %w", err)
// 	}

// 	return nil
// }

func (s *Session) ValidateSession(ctx context.Context) error {
	opts := rest.Opts{
		Method:        "POST",
		Path:          "/validate",
		ExtraHeaders:  s.GetHeaders(map[string]string{}),
		RootURL:       setupEndpoint,
		ContentLength: common.Int64(0),
	}
	_, err := s.Request(ctx, opts, nil, &s.AccountInfo)
	if err != nil {
		return fmt.Errorf("validateSession failed: %w", err)
	}

	return nil
}

// func (s *Session) ValidateSession(ctx context.Context) error {
// 	// headers := GetCommonHeaders(map[string]string{})
// 	//headers["X-Apple-ID-Session-Id"] = s.SessionID

// 	opts := rest.Opts{
// 		Method:        "POST",
// 		Path:          "/validate",
// 		ExtraHeaders:  s.GetHeaders(map[string]string{}),
// 		RootURL:       setupEndpoint,
// 		ContentLength: common.Int64(0),
// 	}
// 	// spew.Dump(srv.Cookies())
// 	// _, err := srv.CallJSON(ctx, &opts, nil, &s.AccountInfo)
// 	// _, err := srv.CallJSON(ctx, &opts, nil, &s.AccountInfo)
// 	_, err := s.Request(ctx, opts, nil, &s.AccountInfo)
// 	// spew.Dump(resp)
// 	if err != nil {
// 		return fmt.Errorf("validateSession failed: %w", err)
// 	}
// 	// s.Cookies, _ = MergeCookies(s.Cookies, resp.Cookies())
// 	// srv.SetCookie(s.Cookies...)
// 	return nil
// }

func (s *Session) GetAuthHeaders(overwrite map[string]string) map[string]string {
	headers := map[string]string{
		// "Accept": "*.*",
		"Accept":                           "application/json",
		"Content-Type":                     "application/json",
		"X-Apple-OAuth-Client-Id":          "d39ba9916b7251055b22c7f910e2ea796ee65e98b2ddecea8f5dde8d9d1a815d",
		"X-Apple-OAuth-Client-Type":        "firstPartyAuth",
		"X-Apple-OAuth-Redirect-URI":       "https://www.icloud.com",
		"X-Apple-OAuth-Require-Grant-Code": "true",
		"X-Apple-OAuth-Response-Mode":      "web_message",
		"X-Apple-OAuth-Response-Type":      "code",
		"X-Apple-OAuth-State":              s.ClientID,
		"X-Apple-Widget-Key":               "d39ba9916b7251055b22c7f910e2ea796ee65e98b2ddecea8f5dde8d9d1a815d",
		"Origin":                           homeEndpoint,
		"Referer":                          fmt.Sprintf("%s/", homeEndpoint),
		"User-Agent":                       "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:103.0) Gecko/20100101 Firefox/103.0",
	}
	for k, v := range overwrite {
		headers[k] = v
	}
	return headers
}

// GetHeaders: Gets the authentication headers required for a request
func (s *Session) GetHeaders(overwrite map[string]string) map[string]string { //            "Accept": "*/*",
	headers := GetCommonHeaders(map[string]string{})
	headers["Cookie"] = s.GetCookieString()
	for k, v := range overwrite {
		headers[k] = v
	}
	return headers
}

// we only care about name and value.
func (s *Session) GetCookieString() string { //            "Accept": "*/*",
	cookieHeader := ""
	for _, cookie := range s.Cookies {
		cookieHeader = cookieHeader + cookie.Name + "=" + cookie.Value + ";"
	}
	return cookieHeader
}

func GetCommonHeaders(overwrite map[string]string) map[string]string { //            "Accept": "*/*",
	headers := map[string]string{
		"Content-Type": "application/json",
		"Origin":       baseEndpoint,
		"Referer":      fmt.Sprintf("%s/", baseEndpoint),
		"User-Agent":   "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:103.0) Gecko/20100101 Firefox/103.0",
	}
	for k, v := range overwrite {
		headers[k] = v
	}
	return headers
}

func MergeCookies(left []*http.Cookie, right []*http.Cookie) ([]*http.Cookie, error) {
	var hashes []string
	for _, cookie := range right {
		hashes = append(hashes, cookie.Raw)
	}
	for _, cookie := range left {
		if !slices.Contains(hashes, cookie.Raw) {
			right = append(right, cookie)
		}
	}
	return right, nil
}

func GetCookiesForDomain(url *url.URL, cookies []*http.Cookie) ([]*http.Cookie, error) {
	var domain_cookies []*http.Cookie
	for _, cookie := range cookies {
		if strings.HasSuffix(url.Host, cookie.Domain) {
			domain_cookies = append(domain_cookies, cookie)
		}
	}
	return domain_cookies, nil
}

// var contextHeader = map[string]func(d *Session, v string){
// 	"X-Apple-ID-Account-Country": func(d *Session, v string) {
// 		d.AccountCountry = v
// 	},
// 	"X-Apple-ID-Session-Id": func(d *Session, v string) {
// 		d.SessionID = v
// 	},
// 	"X-Apple-Session-Token": func(d *Session, v string) {
// 		d.SessionToken = v
// 	},
// 	"X-Apple-TwoSV-Trust-Token": func(d *Session, v string) {
// 		d.TrustToken = v
// 	},
// 	"scnt": func(d *Session, v string) {
// 		d.Scnt = v
// 	},
// }

func NewSession() *Session {
	session := &Session{}
	// if load {
	// 	session.Load()
	// }
	// if session.ClientID == "" {
	// 	session.ClientID = "auth-" + uuid.New().String()
	// }
	session.srv = rest.NewClient(fshttp.NewClient(context.Background())).SetRoot(baseEndpoint)
	session.ClientID = "auth-" + uuid.New().String()
	//session.CookieJar, _ = cookiejar.New(&cookiejar.Options{})
	return session
}

type AccountInfo struct {
	DsInfo                       *ValidateDataDsInfo    `json:"dsInfo"`
	HasMinimumDeviceForPhotosWeb bool                   `json:"hasMinimumDeviceForPhotosWeb"`
	ICDPEnabled                  bool                   `json:"iCDPEnabled"`
	Webservices                  map[string]*webService `json:"webservices"`
	PcsEnabled                   bool                   `json:"pcsEnabled"`
	TermsUpdateNeeded            bool                   `json:"termsUpdateNeeded"`
	ConfigBag                    struct {
		Urls struct {
			AccountCreateUI     string `json:"accountCreateUI"`
			AccountLoginUI      string `json:"accountLoginUI"`
			AccountLogin        string `json:"accountLogin"`
			AccountRepairUI     string `json:"accountRepairUI"`
			DownloadICloudTerms string `json:"downloadICloudTerms"`
			RepairDone          string `json:"repairDone"`
			AccountAuthorizeUI  string `json:"accountAuthorizeUI"`
			VettingUrlForEmail  string `json:"vettingUrlForEmail"`
			AccountCreate       string `json:"accountCreate"`
			GetICloudTerms      string `json:"getICloudTerms"`
			VettingUrlForPhone  string `json:"vettingUrlForPhone"`
		} `json:"urls"`
		AccountCreateEnabled bool `json:"accountCreateEnabled"`
	} `json:"configBag"`
	HsaTrustedBrowser            bool     `json:"hsaTrustedBrowser"`
	AppsOrder                    []string `json:"appsOrder"`
	Version                      int      `json:"version"`
	IsExtendedLogin              bool     `json:"isExtendedLogin"`
	PcsServiceIdentitiesIncluded bool     `json:"pcsServiceIdentitiesIncluded"`
	IsRepairNeeded               bool     `json:"isRepairNeeded"`
	HsaChallengeRequired         bool     `json:"hsaChallengeRequired"`
	RequestInfo                  struct {
		Country  string `json:"country"`
		TimeZone string `json:"timeZone"`
		Region   string `json:"region"`
	} `json:"requestInfo"`
	PcsDeleted bool `json:"pcsDeleted"`
	ICloudInfo struct {
		SafariBookmarksHasMigratedToCloudKit bool `json:"SafariBookmarksHasMigratedToCloudKit"`
	} `json:"iCloudInfo"`
	Apps map[string]*ValidateDataApp `json:"apps"`
}

type ValidateDataDsInfo struct {
	HsaVersion                         int           `json:"hsaVersion"`
	LastName                           string        `json:"lastName"`
	ICDPEnabled                        bool          `json:"iCDPEnabled"`
	TantorMigrated                     bool          `json:"tantorMigrated"`
	Dsid                               string        `json:"dsid"`
	HsaEnabled                         bool          `json:"hsaEnabled"`
	IsHideMyEmailSubscriptionActive    bool          `json:"isHideMyEmailSubscriptionActive"`
	IroncadeMigrated                   bool          `json:"ironcadeMigrated"`
	Locale                             string        `json:"locale"`
	BrZoneConsolidated                 bool          `json:"brZoneConsolidated"`
	ICDRSCapableDeviceList             string        `json:"ICDRSCapableDeviceList"`
	IsManagedAppleID                   bool          `json:"isManagedAppleID"`
	IsCustomDomainsFeatureAvailable    bool          `json:"isCustomDomainsFeatureAvailable"`
	IsHideMyEmailFeatureAvailable      bool          `json:"isHideMyEmailFeatureAvailable"`
	ContinueOnDeviceEligibleDeviceInfo []string      `json:"ContinueOnDeviceEligibleDeviceInfo"`
	Gilligvited                        bool          `json:"gilligvited"`
	AppleIdAliases                     []interface{} `json:"appleIdAliases"`
	UbiquityEOLEnabled                 bool          `json:"ubiquityEOLEnabled"`
	IsPaidDeveloper                    bool          `json:"isPaidDeveloper"`
	CountryCode                        string        `json:"countryCode"`
	NotificationId                     string        `json:"notificationId"`
	PrimaryEmailVerified               bool          `json:"primaryEmailVerified"`
	ADsID                              string        `json:"aDsID"`
	Locked                             bool          `json:"locked"`
	ICDRSCapableDeviceCount            int           `json:"ICDRSCapableDeviceCount"`
	HasICloudQualifyingDevice          bool          `json:"hasICloudQualifyingDevice"`
	PrimaryEmail                       string        `json:"primaryEmail"`
	AppleIdEntries                     []struct {
		IsPrimary bool   `json:"isPrimary"`
		Type      string `json:"type"`
		Value     string `json:"value"`
	} `json:"appleIdEntries"`
	GilliganEnabled    bool   `json:"gilligan-enabled"`
	IsWebAccessAllowed bool   `json:"isWebAccessAllowed"`
	FullName           string `json:"fullName"`
	MailFlags          struct {
		IsThreadingAvailable           bool `json:"isThreadingAvailable"`
		IsSearchV2Provisioned          bool `json:"isSearchV2Provisioned"`
		SCKMail                        bool `json:"sCKMail"`
		IsMppSupportedInCurrentCountry bool `json:"isMppSupportedInCurrentCountry"`
	} `json:"mailFlags"`
	LanguageCode         string `json:"languageCode"`
	AppleId              string `json:"appleId"`
	HasUnreleasedOS      bool   `json:"hasUnreleasedOS"`
	AnalyticsOptInStatus bool   `json:"analyticsOptInStatus"`
	FirstName            string `json:"firstName"`
	ICloudAppleIdAlias   string `json:"iCloudAppleIdAlias"`
	NotesMigrated        bool   `json:"notesMigrated"`
	BeneficiaryInfo      struct {
		IsBeneficiary bool `json:"isBeneficiary"`
	} `json:"beneficiaryInfo"`
	HasPaymentInfo bool   `json:"hasPaymentInfo"`
	PcsDelet       bool   `json:"pcsDelet"`
	AppleIdAlias   string `json:"appleIdAlias"`
	BrMigrated     bool   `json:"brMigrated"`
	StatusCode     int    `json:"statusCode"`
	FamilyEligible bool   `json:"familyEligible"`
}

type ValidateDataApp struct {
	CanLaunchWithOneFactor bool `json:"canLaunchWithOneFactor"`
	IsQualifiedForBeta     bool `json:"isQualifiedForBeta"`
}

type webService struct {
	PcsRequired bool   `json:"pcsRequired"`
	URL         string `json:"url"`
	UploadURL   string `json:"uploadUrl"`
	Status      string `json:"status"`
}
