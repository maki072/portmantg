// Package telemt provides a client for the telemt proxy API.
package telemt

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Client is a telemt API client.
type Client struct {
	base string
	http *http.Client
}

// New creates a new telemt client.
func New(baseURL string) *Client {
	return &Client{
		base: baseURL,
		http: &http.Client{Timeout: 10 * time.Second},
	}
}

type createUserReq struct {
	Username string `json:"username"`
	Secret   string `json:"secret"`
}

type apiResponse struct {
	Ok   bool            `json:"ok"`
	Data json.RawMessage `json:"data"`
}

// CreateUser registers a new user in telemt.
func (c *Client) CreateUser(username, secret string) error {
	body, _ := json.Marshal(createUserReq{Username: username, Secret: secret})
	resp, err := c.http.Post(c.base+"/v1/users", "application/json", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("telemt create user: %w", err)
	}
	defer resp.Body.Close()

	var r apiResponse
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return fmt.Errorf("telemt decode response: %w", err)
	}
	if !r.Ok {
		return fmt.Errorf("telemt returned not ok: %s", r.Data)
	}
	return nil
}

// DeleteUser removes a user from telemt.
func (c *Client) DeleteUser(username string) error {
	req, _ := http.NewRequest(http.MethodDelete, c.base+"/v1/users/"+username, nil)
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("telemt delete user: %w", err)
	}
	defer resp.Body.Close()

	b, _ := io.ReadAll(resp.Body)
	var r apiResponse
	if err := json.Unmarshal(b, &r); err != nil {
		return fmt.Errorf("telemt decode response: %w", err)
	}
	if !r.Ok {
		return fmt.Errorf("telemt returned not ok: %s", r.Data)
	}
	return nil
}
