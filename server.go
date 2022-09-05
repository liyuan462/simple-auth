package main

import (
	"encoding/json"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

// Server represents the service.
type Server struct {
	conf       *Config
	userIndex  *Index[*User]
	roleIndex  *Index[*Role]
	tokenIndex *Index[*Token]
}

// Config is the configuration for this service.
type Config struct {
	// the lifetime of token in seconds
	TokenLifetime int64

	UserNameMinLength int
	UserNameMaxLength int
	PasswordMinLength int
	PasswordMaxLength int
	RoleNameMinLength int
	RoleNameMaxLength int
}

var defaultConf = &Config{
	TokenLifetime:     2 * 3600,
	UserNameMinLength: 3,
	UserNameMaxLength: 32,
	PasswordMinLength: 8,
	PasswordMaxLength: 32,
	RoleNameMinLength: 3,
	RoleNameMaxLength: 32,
}

type User struct {
	Mu       sync.RWMutex    `json:"-"`
	Name     string          `json:"name"`
	Password string          `json:"password"`
	Salt     string          `json:"-"`
	Roles    map[string]bool `json:"-"`
	Token    string          `json:"-"`
}

func (user *User) AddRole(name string) {
	user.Mu.Lock()
	defer user.Mu.Unlock()
	user.Roles[name] = true
}

func (user *User) DeleteRole(name string) {
	user.Mu.Lock()
	defer user.Mu.Unlock()
	delete(user.Roles, name)
}

func (user *User) GetRole(name string) bool {
	user.Mu.RLock()
	defer user.Mu.RUnlock()
	return user.Roles[name]
}

type Role struct {
	Name string `json:"name"`
}

type Token struct {
	Value    string
	Expire   int64
	UserName string
}

type Index[T any] struct {
	Mu   sync.RWMutex
	Data map[string]T
}

func (index *Index[T]) Set(name string, value T) {
	index.Mu.Lock()
	defer index.Mu.Unlock()
	index.Data[name] = value
}

func (index *Index[T]) Get(name string) T {
	index.Mu.RLock()
	defer index.Mu.RUnlock()
	return index.Data[name]
}

func (index *Index[T]) Delete(name string) {
	index.Mu.Lock()
	defer index.Mu.Unlock()
	delete(index.Data, name)
}

type Response struct {
	Code RespCode    `json:"code"`
	Msg  string      `json:"msg"`
	Data interface{} `json:"data"`
}

type RespCode int

const (
	RespCodeOK                   = iota // 0
	RespCodeInternalError               // 1
	RespCodeInvalidParams               // 2
	RespCodeUserExists                  // 3
	RespCodeInvalidUser                 // 4
	RespCodeRoleExists                  // 5
	RespCodeInvalidRole                 // 6
	RespCodeAuthenticationFailed        // 7
	RespCodeInvalidToken                // 8
)

var errMsgs = map[RespCode]string{
	RespCodeOK:                   "ok",
	RespCodeInternalError:        "internal error",
	RespCodeInvalidParams:        "invalid param",
	RespCodeUserExists:           "user already exists",
	RespCodeInvalidUser:          "invalid user",
	RespCodeRoleExists:           "role already exists",
	RespCodeInvalidRole:          "invalid role",
	RespCodeAuthenticationFailed: "authentication failed",
	RespCodeInvalidToken:         "invalid token",
}

func newServer(conf *Config) *Server {
	s := &Server{
		conf:       conf,
		userIndex:  &Index[*User]{Data: make(map[string]*User)},
		roleIndex:  &Index[*Role]{Data: make(map[string]*Role)},
		tokenIndex: &Index[*Token]{Data: make(map[string]*Token)},
	}

	if s.conf == nil {
		s.conf = defaultConf
	}

	return s
}

func main() {
	server := newServer(nil)
	http.HandleFunc("/user/create", server.createUser)
	http.HandleFunc("/user/delete", server.deleteUser)
	http.HandleFunc("/role/create", server.createRole)
	http.HandleFunc("/role/delete", server.deleteRole)
	http.HandleFunc("/user/role/add", server.addUserRole)
	http.HandleFunc("/user/authenticate", server.authenticateUser)
	http.HandleFunc("/user/token/invalidate", server.invalidateToken)
	http.HandleFunc("/user/role/check", server.checkUserRole)
	http.HandleFunc("/user/role/list", server.listUserRole)
	log.Fatal(http.ListenAndServe(":8081", nil))
}

func (server *Server) createUser(w http.ResponseWriter, req *http.Request) {
	// how to hash password: https://security.stackexchange.com/questions/211/how-to-securely-hash-passwords
	// we use bcrypt(password + salt)

	decoder := json.NewDecoder(req.Body)
	var user User
	err := decoder.Decode(&user)
	if err != nil {
		log.Printf("parse json error: %v", err)
		respError(w, RespCodeInvalidParams)
		return
	}

	// check params, user name and password length limit
	if (len(user.Name) < server.conf.UserNameMinLength || len(user.Name) > server.conf.UserNameMaxLength) ||
		(len(user.Password) < server.conf.PasswordMinLength || len(user.Password) > server.conf.PasswordMaxLength) {
		respError(w, RespCodeInvalidParams)
		return
	}

	// check if user exists
	if server.userIndex.Get(user.Name) != nil {
		respError(w, RespCodeUserExists)
		return
	}

	// generate salt
	uuidResult, err := uuid.NewRandom()
	if err != nil {
		log.Printf("new uuid error: %v", err)
		respError(w, RespCodeInternalError)
		return
	}
	user.Salt = uuidResult.String()

	// hash password
	passwordBytes, err := bcrypt.GenerateFromPassword([]byte(user.Password+user.Salt), bcrypt.DefaultCost)
	if err != nil {
		log.Printf("bcrypt hash error: %v", err)
		respError(w, RespCodeInternalError)
		return
	}

	user.Password = string(passwordBytes)

	user.Roles = make(map[string]bool)

	// create user
	server.userIndex.Set(user.Name, &user)

	respOK(w)
}

func (server *Server) deleteUser(w http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(req.Body)
	var user User
	err := decoder.Decode(&user)
	if err != nil {
		log.Printf("parse json error: %v", err)
		respError(w, RespCodeInvalidParams)
		return
	}

	// check if user exists
	if server.userIndex.Get(user.Name) == nil {
		respError(w, RespCodeInvalidUser)
		return
	}

	// delete user token
	server.tokenIndex.Delete(user.Token)

	// delete user
	server.userIndex.Delete(user.Name)

	respOK(w)
}

func (server *Server) createRole(w http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(req.Body)
	var role Role
	err := decoder.Decode(&role)
	if err != nil {
		log.Printf("parse json error: %v", err)
		respError(w, RespCodeInvalidParams)
		return
	}

	// check params, role name length limit
	if len(role.Name) < server.conf.RoleNameMinLength || len(role.Name) > server.conf.RoleNameMaxLength {
		respError(w, RespCodeInvalidParams)
		return
	}
	// check if role exists
	if server.roleIndex.Get(role.Name) != nil {
		respError(w, RespCodeRoleExists)
		return
	}

	// create role
	server.roleIndex.Set(role.Name, &role)
	respOK(w)
}

func (server *Server) deleteRole(w http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(req.Body)
	var role Role
	err := decoder.Decode(&role)
	if err != nil {
		log.Printf("parse json error: %v", err)
		respError(w, RespCodeInvalidParams)
		return
	}

	// check if role exists
	if server.roleIndex.Get(role.Name) == nil {
		respError(w, RespCodeInvalidRole)
		return
	}

	// We assume the deleteRole operation is rare, so we can do something that is not so efficient.
	// delete this role from all users.
	server.userIndex.Mu.RLock()
	for _, user := range server.userIndex.Data {
		user.DeleteRole(role.Name)
	}
	server.userIndex.Mu.RUnlock()

	// delete role
	server.roleIndex.Delete(role.Name)
	respOK(w)
}

func (server *Server) addUserRole(w http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(req.Body)
	var request struct {
		UserName string `json:"user_name"`
		RoleName string `json:"role_name"`
	}
	err := decoder.Decode(&request)
	if err != nil {
		log.Printf("parse json error: %v", err)
		respError(w, RespCodeInvalidParams)
		return
	}

	// get user
	user := server.userIndex.Get(request.UserName)
	if user == nil {
		respError(w, RespCodeInvalidUser)
		return
	}

	// get role
	if server.roleIndex.Get(request.RoleName) == nil {
		respError(w, RespCodeInvalidRole)
		return
	}

	// add role to user
	user.AddRole(request.RoleName)
	respOK(w)
}

func (server *Server) authenticateUser(w http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(req.Body)
	var reqUser User
	err := decoder.Decode(&reqUser)
	if err != nil {
		log.Printf("parse json error: %v", err)
		respError(w, RespCodeInvalidParams)
		return
	}

	// get user
	user := server.userIndex.Get(reqUser.Name)
	if user == nil {
		respError(w, RespCodeAuthenticationFailed)
		return
	}

	// check password
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(reqUser.Password+user.Salt)); err != nil {
		respError(w, RespCodeAuthenticationFailed)
		return
	}

	// whenever it's called, generate a new token
	uuidResult, err := uuid.NewRandom()
	if err != nil {
		log.Printf("new uuid error: %v", err)
		respError(w, RespCodeInternalError)
		return
	}

	token := &Token{
		Value:    uuidResult.String(),
		Expire:   time.Now().Unix() + server.conf.TokenLifetime,
		UserName: user.Name,
	}

	server.tokenIndex.Set(token.Value, token)

	// delete the user's old token.
	if user.Token != "" {
		server.tokenIndex.Delete(user.Token)
	}

	// update the user's token.
	user.Token = token.Value

	respData(w, map[string]interface{}{"token": user.Token})
}

func (server *Server) invalidateToken(w http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(req.Body)
	var request struct {
		Token string `json:"token"`
	}
	err := decoder.Decode(&request)
	if err != nil {
		log.Printf("parse json error: %v", err)
		respError(w, RespCodeInvalidParams)
		return
	}

	// Here we just delete token from tokenIndex.
	// If the token is expired or not valid, delete will be also be ok.
	// Need to reset the user's token field? We choose not to, because the token index is the single source of truth.
	server.tokenIndex.Delete(request.Token)

	respOK(w)
}

func (server *Server) checkUserRole(w http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(req.Body)
	var request struct {
		Token    string `json:"token"`
		RoleName string `json:"role_name"`
	}
	err := decoder.Decode(&request)
	if err != nil {
		log.Printf("parse json error: %v", err)
		respError(w, RespCodeInvalidParams)
		return
	}

	user, respCode := server.validateToken(request.Token)
	if user == nil {
		respError(w, respCode)
		return
	}

	hasRole := user.GetRole(request.RoleName)

	respData(w, map[string]interface{}{"hasRole": hasRole})
}

func (server *Server) listUserRole(w http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(req.Body)
	var request struct {
		Token string `json:"token"`
	}
	err := decoder.Decode(&request)
	if err != nil {
		log.Printf("parse json error: %v", err)
		respError(w, RespCodeInvalidParams)
		return
	}

	user, respCode := server.validateToken(request.Token)
	if user == nil {
		respError(w, respCode)
		return
	}

	var roles []string
	user.Mu.RLock()
	for role := range user.Roles {
		roles = append(roles, role)
	}
	user.Mu.RUnlock()

	respData(w, map[string]interface{}{"roles": roles})
}

func (server *Server) validateToken(tokenValue string) (*User, RespCode) {
	// get token
	token := server.tokenIndex.Get(tokenValue)

	// token invalid
	if token == nil {
		return nil, RespCodeInvalidToken
	}

	// token expired
	if token.Expire < time.Now().Unix() {
		// clear expired token to save space.
		server.tokenIndex.Delete(tokenValue)
		return nil, RespCodeInvalidToken
	}

	user := server.userIndex.Get(token.UserName)
	if user == nil {
		// this should not happen, because when we delete user, we delete token first.
		// we log it in case it happened due to some bug.
		log.Printf("user is deleted before token is deleted, user: %s, token: %s", token.UserName, token.Value)
		return nil, RespCodeInternalError
	}

	return user, RespCodeOK
}

func respError(w http.ResponseWriter, code RespCode) {
	respAll(w, code, nil)
}

func respOK(w http.ResponseWriter) {
	respData(w, nil)
}

func respData(w http.ResponseWriter, data interface{}) {
	respAll(w, RespCodeOK, data)
}

func respAll(w http.ResponseWriter, code RespCode, data interface{}) {
	encoder := json.NewEncoder(w)
	err := encoder.Encode(Response{
		Code: code,
		Msg:  errMsgs[code],
		Data: data,
	})
	if err != nil {
		log.Printf("encrypt resp data error: %v", err)
		respError(w, RespCodeInternalError)
	}
}
