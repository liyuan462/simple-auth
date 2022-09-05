package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestCreateUser(t *testing.T) {
	server := newServer(nil)
	t.Run("failed to create a user due to invalid username length", func(t *testing.T) {
		request := newRequest("/user/create", strings.NewReader(`{
"name": "ab",
"password": "123456789"
}`))
		response := httptest.NewRecorder()
		server.createUser(response, request)
		resp := getResponse(t, response.Body)

		assertRespCode(t, resp.Code, RespCodeInvalidParams)
	})

	t.Run("failed to create a user due to invalid password length", func(t *testing.T) {
		request := newRequest("/user/create", strings.NewReader(`{
"name": "Jack",
"password": "1234567"
}`))
		response := httptest.NewRecorder()
		server.createUser(response, request)
		resp := getResponse(t, response.Body)

		assertRespCode(t, resp.Code, RespCodeInvalidParams)
	})

	t.Run("succeed to create a new user", func(t *testing.T) {
		request := newRequest("/user/create", strings.NewReader(`{
"name": "Jack",
"password": "12345678"
}`))
		response := httptest.NewRecorder()
		server.createUser(response, request)
		resp := getResponse(t, response.Body)

		assertRespCode(t, resp.Code, RespCodeOK)

		// test if the password is hashed.
		hashedPassword := server.userIndex.Get("Jack").Password
		if hashedPassword == "12345678" {
			t.Errorf("password is saved literally!")
		}
	})

	t.Run("succeed to create another new user", func(t *testing.T) {
		request := newRequest("/user/create", strings.NewReader(`{
"name": "John",
"password": "asadfs234"
}`))
		response := httptest.NewRecorder()
		server.createUser(response, request)
		resp := getResponse(t, response.Body)

		assertRespCode(t, resp.Code, RespCodeOK)
	})

	t.Run("failed to create an existed user", func(t *testing.T) {
		request := newRequest("/user/create", strings.NewReader(`{
"name": "Jack",
"password": "12345678"
}`))
		response := httptest.NewRecorder()
		server.createUser(response, request)
		resp := getResponse(t, response.Body)

		assertRespCode(t, resp.Code, RespCodeUserExists)
	})

}

func TestDeleteUser(t *testing.T) {
	server := newServer(nil)
	t.Run("succeed to delete an existed user", func(t *testing.T) {
		// first create a user
		server.createUser(httptest.NewRecorder(), newRequest("/user/create", strings.NewReader(`{
"name": "Jack",
"password": "12345678"
}`)))

		// then delete the user
		request := newRequest("/user/delete", strings.NewReader(`{
"name": "Jack"
}`))
		response := httptest.NewRecorder()
		server.deleteUser(response, request)
		resp := getResponse(t, response.Body)

		assertRespCode(t, resp.Code, RespCodeOK)
	})

	t.Run("failed to delete an invalid user", func(t *testing.T) {
		request := newRequest("/user/delete", strings.NewReader(`{
"name": "Bob"
}`))
		response := httptest.NewRecorder()
		server.deleteUser(response, request)
		resp := getResponse(t, response.Body)

		assertRespCode(t, resp.Code, RespCodeInvalidUser)
	})
}

func TestCreateRole(t *testing.T) {
	server := newServer(nil)
	t.Run("failed to create a role due to invalid role name length", func(t *testing.T) {
		request := newRequest("/role/create", strings.NewReader(`{
"name": "ab"
}`))
		response := httptest.NewRecorder()
		server.createRole(response, request)
		resp := getResponse(t, response.Body)

		assertRespCode(t, resp.Code, RespCodeInvalidParams)
	})

	t.Run("succeed to create a new role", func(t *testing.T) {
		request := newRequest("/role/create", strings.NewReader(`{
"name": "admin"
}`))
		response := httptest.NewRecorder()
		server.createRole(response, request)
		resp := getResponse(t, response.Body)

		assertRespCode(t, resp.Code, RespCodeOK)
	})

	t.Run("succeed to create another new role", func(t *testing.T) {
		request := newRequest("/role/create", strings.NewReader(`{
"name": "user"
}`))
		response := httptest.NewRecorder()
		server.createRole(response, request)
		resp := getResponse(t, response.Body)

		assertRespCode(t, resp.Code, RespCodeOK)
	})

	t.Run("failed to create an existed role", func(t *testing.T) {
		request := newRequest("/role/create", strings.NewReader(`{
"name": "admin"
}`))
		response := httptest.NewRecorder()
		server.createRole(response, request)
		resp := getResponse(t, response.Body)

		assertRespCode(t, resp.Code, RespCodeRoleExists)
	})

}

func TestDeleteRole(t *testing.T) {
	server := newServer(nil)
	t.Run("succeed to delete an existed role", func(t *testing.T) {
		// first create a role
		server.createRole(httptest.NewRecorder(), newRequest("/role/create", strings.NewReader(`{
"name": "user"
}`)))

		// then delete the role
		request := newRequest("/role/delete", strings.NewReader(`{
"name": "user"
}`))
		response := httptest.NewRecorder()
		server.deleteRole(response, request)
		resp := getResponse(t, response.Body)

		assertRespCode(t, resp.Code, RespCodeOK)
	})

	t.Run("failed to delete an invalid role", func(t *testing.T) {
		request := newRequest("/role/delete", strings.NewReader(`{
"name": "other"
}`))
		response := httptest.NewRecorder()
		server.deleteRole(response, request)
		resp := getResponse(t, response.Body)

		assertRespCode(t, resp.Code, RespCodeInvalidRole)
	})
}

func TestAddUserRole(t *testing.T) {
	server := newServer(nil)
	t.Run("failed to add user role due to invalid user", func(t *testing.T) {
		request := newRequest("/user/role/add", strings.NewReader(`{
"user_name": "Jack",
"role_name": "admin"
}`))
		response := httptest.NewRecorder()
		server.addUserRole(response, request)
		resp := getResponse(t, response.Body)

		assertRespCode(t, resp.Code, RespCodeInvalidUser)
	})

	t.Run("failed to add user role due to invalid role", func(t *testing.T) {
		// first create the user
		server.createUser(httptest.NewRecorder(), newRequest("/user/create", strings.NewReader(`{
"name": "Jack",
"password": "12345678"
}`)))

		// then add a role to the user
		request := newRequest("/user/role/add", strings.NewReader(`{
"user_name": "Jack",
"role_name": "admin"
}`))
		response := httptest.NewRecorder()
		server.addUserRole(response, request)
		resp := getResponse(t, response.Body)

		assertRespCode(t, resp.Code, RespCodeInvalidRole)
	})

	t.Run("succeed to add user role", func(t *testing.T) {
		// first create the role
		server.createRole(httptest.NewRecorder(), newRequest("/role/create", strings.NewReader(`{
"name": "admin"
}`)))

		// then add a role to the user
		request := newRequest("/user/role/add", strings.NewReader(`{
"user_name": "Jack",
"role_name": "admin"
}`))
		response := httptest.NewRecorder()
		server.addUserRole(response, request)
		resp := getResponse(t, response.Body)

		assertRespCode(t, resp.Code, RespCodeOK)
	})

	t.Run("succeed to add user role if the user already have the role", func(t *testing.T) {
		request := newRequest("/user/role/add", strings.NewReader(`{
"user_name": "Jack",
"role_name": "admin"
}`))
		response := httptest.NewRecorder()
		server.addUserRole(response, request)
		resp := getResponse(t, response.Body)

		assertRespCode(t, resp.Code, RespCodeOK)
	})

}

func TestAuthenticateUser(t *testing.T) {
	server := newServer(nil)
	t.Run("failed to authenticate due to invalid user", func(t *testing.T) {
		request := newRequest("/user/authenticate", strings.NewReader(`{
"name": "John",
"password": "12345678"
}`))
		response := httptest.NewRecorder()
		server.authenticateUser(response, request)
		resp := getResponse(t, response.Body)

		assertRespCode(t, resp.Code, RespCodeAuthenticationFailed)
	})

	// create a user
	server.createUser(httptest.NewRecorder(), newRequest("/user/create", strings.NewReader(`{
"name": "Jack",
"password": "12345678"
}`)))

	t.Run("failed to authenticate due to invalid password", func(t *testing.T) {
		request := newRequest("/user/authenticate", strings.NewReader(`{
"name": "Jack",
"password": "123456789"
}`))
		response := httptest.NewRecorder()
		server.authenticateUser(response, request)
		resp := getResponse(t, response.Body)

		assertRespCode(t, resp.Code, RespCodeAuthenticationFailed)
	})

	t.Run("succeed to authenticate a user", func(t *testing.T) {
		request := newRequest("/user/authenticate", strings.NewReader(`{
"name": "Jack",
"password": "12345678"
}`))
		response := httptest.NewRecorder()
		server.authenticateUser(response, request)
		resp := getResponse(t, response.Body)

		assertRespCode(t, resp.Code, RespCodeOK)
		m := resp.Data.(map[string]interface{})

		// check if the token is empty
		if m["token"] == "" {
			t.Error("got empty token")
		}

		// check if the token is saved to user
		got := server.userIndex.Get("Jack").Token
		if m["token"] != server.userIndex.Get("Jack").Token {
			t.Errorf("token not saved to user, user: %s, token: %s", got, m["token"])
		}
	})
}

func TestInvalidateToken(t *testing.T) {
	server := newServer(nil)

	// create a user
	server.createUser(httptest.NewRecorder(), newRequest("/user/create", strings.NewReader(`{
"name": "Jack",
"password": "12345678"
}`)))

	// generate a token for the user
	response := httptest.NewRecorder()
	server.authenticateUser(response, newRequest("/user/authenticate", strings.NewReader(`{
"name": "Jack",
"password": "12345678"
}`)))
	resp := getResponse(t, response.Body)
	token := resp.Data.(map[string]interface{})["token"].(string)

	tokenObj := server.tokenIndex.Get(token)
	if tokenObj == nil || tokenObj.Value != token {
		t.Errorf("token not saved to index, token: %s", token)
	}

	t.Run("succeed to invalid a valid token", func(t *testing.T) {
		request := newRequest("/user/token/invalidate", strings.NewReader(fmt.Sprintf(`{
"token": "%s"
}`, token)))
		response := httptest.NewRecorder()
		server.invalidateToken(response, request)
		resp := getResponse(t, response.Body)

		assertRespCode(t, resp.Code, RespCodeOK)
		if server.tokenIndex.Get(token) != nil {
			t.Errorf("failed to invalidate token: %s", token)
		}
	})

	t.Run("invalidation will be succeesful even if the token is invalid", func(t *testing.T) {
		request := newRequest("/user/token/invalidate", strings.NewReader(`{
"token": "not valid token"
}`))
		response := httptest.NewRecorder()
		server.invalidateToken(response, request)
		resp := getResponse(t, response.Body)

		assertRespCode(t, resp.Code, RespCodeOK)
		if server.tokenIndex.Get(token) != nil {
			t.Errorf("failed to invalidate token: %s", token)
		}
	})

}

func TestCheckUserRole(t *testing.T) {
	server := newServer(nil)

	t.Run("failed to check user role due to invalid token", func(t *testing.T) {
		request := newRequest("/user/role/check", strings.NewReader(`{
"token": "asdfasdfasdfas"
}`))
		response := httptest.NewRecorder()
		server.checkUserRole(response, request)
		resp := getResponse(t, response.Body)

		assertRespCode(t, resp.Code, RespCodeInvalidToken)
	})

	// create a user
	server.createUser(httptest.NewRecorder(), newRequest("/user/create", strings.NewReader(`{
"name": "Jack",
"password": "12345678"
}`)))

	// create a role
	server.createRole(httptest.NewRecorder(), newRequest("/role/create", strings.NewReader(`{
"name": "admin"
}`)))

	// generate a token for the user
	response := httptest.NewRecorder()
	server.authenticateUser(response, newRequest("/user/authenticate", strings.NewReader(`{
"name": "Jack",
"password": "12345678"
}`)))
	resp := getResponse(t, response.Body)
	token := resp.Data.(map[string]interface{})["token"].(string)

	t.Run("user does not have a role", func(t *testing.T) {
		request := newRequest("/user/role/check", strings.NewReader(fmt.Sprintf(`{
"token": "%s",
"role_name": "admin"
}`, token)))

		response := httptest.NewRecorder()
		server.checkUserRole(response, request)
		resp := getResponse(t, response.Body)
		hasRole := resp.Data.(map[string]interface{})["hasRole"].(bool)
		if hasRole {
			t.Error("the user should not have the role")
		}
	})

	// add the role to user
	server.addUserRole(httptest.NewRecorder(), newRequest("/user/role/add", strings.NewReader(`{
"user_name": "Jack",
"role_name": "admin"
}`)))

	t.Run("user does have a role", func(t *testing.T) {
		request := newRequest("/user/role/check", strings.NewReader(fmt.Sprintf(`{
"token": "%s",
"role_name": "admin"
}`, token)))

		response := httptest.NewRecorder()
		server.checkUserRole(response, request)
		resp := getResponse(t, response.Body)
		hasRole := resp.Data.(map[string]interface{})["hasRole"].(bool)
		if !hasRole {
			t.Error("the user should have the role")
		}
	})
}

func TestListUserRole(t *testing.T) {
	server := newServer(nil)

	t.Run("failed to list user role due to invalid token", func(t *testing.T) {
		request := newRequest("/user/role/check", strings.NewReader(`{
"token": "asdfasdfasdfas"
}`))
		response := httptest.NewRecorder()
		server.listUserRole(response, request)
		resp := getResponse(t, response.Body)

		assertRespCode(t, resp.Code, RespCodeInvalidToken)
	})

	// create a user
	server.createUser(httptest.NewRecorder(), newRequest("/user/create", strings.NewReader(`{
"name": "Jack",
"password": "12345678"
}`)))

	// create a role
	server.createRole(httptest.NewRecorder(), newRequest("/role/create", strings.NewReader(`{
"name": "admin"
}`)))

	// generate a token for the user
	response := httptest.NewRecorder()
	server.authenticateUser(response, newRequest("/user/authenticate", strings.NewReader(`{
"name": "Jack",
"password": "12345678"
}`)))
	resp := getResponse(t, response.Body)
	token := resp.Data.(map[string]interface{})["token"].(string)

	t.Run("user does not have a role", func(t *testing.T) {
		request := newRequest("/user/role/list", strings.NewReader(fmt.Sprintf(`{
"token": "%s"
}`, token)))

		response := httptest.NewRecorder()
		server.listUserRole(response, request)
		resp := getRoleListResponse(t, response.Body)
		if len(resp.Data.Roles) != 0 {
			t.Error("the user should not have a role")
		}
	})

	// add the role to user
	server.addUserRole(httptest.NewRecorder(), newRequest("/user/role/add", strings.NewReader(`{
"user_name": "Jack",
"role_name": "admin"
}`)))

	t.Run("user does have a role", func(t *testing.T) {
		request := newRequest("/user/role/list", strings.NewReader(fmt.Sprintf(`{
"token": "%s"
}`, token)))

		response := httptest.NewRecorder()
		server.listUserRole(response, request)
		resp := getRoleListResponse(t, response.Body)
		if len(resp.Data.Roles) != 1 || resp.Data.Roles[0] != "admin" {
			t.Error("the user should have exact one role")
		}
	})

	// create another role
	server.createRole(httptest.NewRecorder(), newRequest("/role/create", strings.NewReader(`{
"name": "user"
}`)))

	// add another role to user
	server.addUserRole(httptest.NewRecorder(), newRequest("/user/role/add", strings.NewReader(`{
"user_name": "Jack",
"role_name": "user"
}`)))

	t.Run("user does have two roles", func(t *testing.T) {
		request := newRequest("/user/role/list", strings.NewReader(fmt.Sprintf(`{
"token": "%s"
}`, token)))

		response := httptest.NewRecorder()
		server.listUserRole(response, request)
		resp := getRoleListResponse(t, response.Body)
		if len(resp.Data.Roles) != 2 || !inList("admin", resp.Data.Roles) || !inList("user", resp.Data.Roles) {
			t.Error("the user should have exact two roles")
		}
	})
}

// TestTokenExpire test if a token will be expired.
func TestTokenExpire(t *testing.T) {
	// first we set a short expire time: 2s
	conf := &Config{
		TokenLifetime:     2,
		UserNameMinLength: 3,
		UserNameMaxLength: 32,
		PasswordMinLength: 8,
		PasswordMaxLength: 32,
		RoleNameMinLength: 3,
		RoleNameMaxLength: 32,
	}

	server := newServer(conf)

	// create a user
	server.createUser(httptest.NewRecorder(), newRequest("/user/create", strings.NewReader(`{
"name": "Jack",
"password": "12345678"
}`)))

	t.Run("token is not expired in its lifetime", func(t *testing.T) {
		// generate a token for the user
		response := httptest.NewRecorder()
		server.authenticateUser(response, newRequest("/user/authenticate", strings.NewReader(`{
"name": "Jack",
"password": "12345678"
}`)))
		resp := getResponse(t, response.Body)
		token := resp.Data.(map[string]interface{})["token"].(string)

		_, code := server.validateToken(token)
		assertRespCode(t, code, RespCodeOK)
	})

	t.Run("token will be expired after its lifetime", func(t *testing.T) {
		// generate a token for the user
		response := httptest.NewRecorder()
		server.authenticateUser(response, newRequest("/user/authenticate", strings.NewReader(`{
	"name": "Jack",
	"password": "12345678"
	}`)))
		resp := getResponse(t, response.Body)
		token := resp.Data.(map[string]interface{})["token"].(string)

		_, code := server.validateToken(token)
		assertRespCode(t, code, RespCodeOK)

		// because the lifetime is 2s, we sleep 3s, then it should be invalidated.
		time.Sleep(3 * time.Second)
		_, code = server.validateToken(token)
		assertRespCode(t, code, RespCodeInvalidToken)
	})

}

func inList(item string, list []string) bool {
	for _, elem := range list {
		if item == elem {
			return true
		}
	}
	return false
}

func assertRespCode(t testing.TB, got RespCode, want int) {
	t.Helper()
	if int(got) != want {
		t.Errorf("got code %d, want %d", got, want)
	}
}

func getResponse(t testing.TB, body io.Reader) (resp Response) {
	t.Helper()
	err := json.NewDecoder(body).Decode(&resp)

	if err != nil {
		t.Fatalf("Unable to parse response from server %q, '%v'", body, err)
	}

	return
}

type RoleListResponse struct {
	Code RespCode `json:"code"`
	Msg  string   `json:"msg"`
	Data struct {
		Roles []string `json:"roles"`
	} `json:"data"`
}

func getRoleListResponse(t testing.TB, body io.Reader) (resp RoleListResponse) {
	t.Helper()
	err := json.NewDecoder(body).Decode(&resp)

	if err != nil {
		t.Fatalf("Unable to parse response from server %q, '%v'", body, err)
	}

	return
}

func newRequest(url string, body io.Reader) *http.Request {
	req, _ := http.NewRequest(http.MethodPost, url, body)
	return req
}
