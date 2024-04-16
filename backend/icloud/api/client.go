package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"

	"github.com/rclone/rclone/fs"
	"github.com/rclone/rclone/fs/fshttp"
	"github.com/rclone/rclone/lib/rest"
)

const (
	baseEndpoint  = "https://www.icloud.com"
	homeEndpoint  = "https://www.icloud.com"
	setupEndpoint = "https://setup.icloud.com/setup/ws/1"
	authEndpoint  = "https://idmsa.apple.com/appleauth/auth"
	clientId      = "e9f98057fb916de2bbd755ef280d7257146a76e5118f27ab2e9a3d065c20c17e"
)

type Client struct {
	appleID  string
	password string
	srv      *rest.Client
	Session  *Session

	drive *DriveService
}

func New(appleID, password, trustToken string, cookies []*http.Cookie) (*Client, error) {
	icloud := &Client{
		appleID:  appleID,
		password: password,
		srv:      rest.NewClient(fshttp.NewClient(context.Background())),
		Session:  NewSession(),
	}

	icloud.Session.TrustToken = trustToken
	icloud.Session.Cookies = cookies
	return icloud, nil
}

func (c *Client) DriveService() (*DriveService, error) {
	if c.drive == nil {
		c.drive, _ = NewDriveService(c)
	}
	return c.drive, nil
}

func (c *Client) Authenticate(ctx context.Context) error {
	{

		if c.Session.Cookies != nil {
			if err := c.Session.ValidateSession(ctx); err == nil {
				fs.Debugf("icloud", "Valid session, no need to reauth")
				return nil
			}
			c.Session.Cookies = nil
		}

		fs.Debugf("icloud", "Authenticating as %s\n", c.appleID)
		err := c.Session.SignIn(ctx, c.appleID, c.password)

		if err == nil {
			return c.Session.AuthWithToken(ctx)
		}
		return err
	}

	// return fmt.Errorf("login failed: %s", strings.Join(errs, "; "))
}

func (c *Client) SignIn(ctx context.Context) error {
	return c.Session.SignIn(ctx, c.appleID, c.password)
}

func IntoReader(values any) (*bytes.Reader, error) {
	m, err := json.Marshal(values)
	if err == nil {
		return bytes.NewReader(m), nil
	}
	return nil, err
}
