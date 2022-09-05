# Simple Auth

Simple Auth is a simple (and possibly not very secure) authentication and authorization service. The service allows users to be authenticated, and authorizes different behavior.

## To start using Simple Auth

### Prerequisites
* An installation of Go 1.18 or later. For installation instructions, see[Installing go](https://go.dev/doc/install)
* A command terminal. Go works well using any terminal on Linux and Mac, and on PowerShell or cmd in Windows.
* The curl tool. On Linux and Mac, this should already be installed. On Windows, it’s included on Windows 10 Insider build 17063 and later. For earlier Windows versions, you might need to install it. For more, see [Tar and Curl Come to Windows](https://docs.microsoft.com/en-us/virtualization/community/team-blog/2017/20171219-tar-and-curl-come-to-windows).

### How to start
1. clone the repository
```bash
git clone https://github.com/liyuan462/simple-auth.git
```

2. cd to the repository
```bash
cd simple-auth
```

3. run the test to make sure the code works
```bash
go test
```

    if you want be see more detail, run:
```bash
go test -v
```

3. run the server
```bash
go run .
```

4. from a new command line window, use curl to make a request to the running service, see following API section.
```bash
curl http://localhost:8081/user/create \
    --include \
    --header "Content-Type: application/json" \
    --request "POST" \
    --data '{"name": "John", "password": "12345678"}'
```

## API
### General Format
All the APIs use the *POST* method. The request params and response data are *both encoded in JSON*.
The response json is in the following format:

```JSON
{
   "code":0, 
   "msg":"ok", 
   "data":{} 
}

```

When everything is OK, the code will be 0, and the data will be a non-null object.
When there is some error, the code will be greater than 0, as following:
```Go
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

```

### Create user
Path: /user/create
Request:
```JSON
{
   "name":"John",             // the username
   "password":"12345678"      // the password
}

```
Response:

```JSON
{
   "code":0,
   "msg":"ok",
   "data":null
}

```

### Delete user
Path: /user/delete
Request:
```JSON
{
   "name":"John"             // the username
}

```
Response:

```JSON
{
   "code":0,
   "msg":"ok",
   "data":null
}

```

### Create role 
Path: /role/create
Request:
```JSON
{
   "name":"admin"             // the role name
}

```
Response:

```JSON
{
   "code":0,
   "msg":"ok",
   "data":null
}

```

### Delete role
Path: /role/delete
Request:
```JSON
{
   "name":"admin"             // the role name
}

```
Response:

```JSON
{
   "code":0,
   "msg":"ok",
   "data":null
}

```

### Add role to user
Path: /user/role/add
Request:
```JSON
{
   "user_name":"iceblue",       // the username
   "role_name":"user"           // the role name
}
```
Response:

```JSON
{
   "code":0,
   "msg":"ok",
   "data":null
}

```

### Authenticate user
Path: /user/authenticate
Request:
```JSON
{
   "name":"John",             // the username
   "password":"12345678"      // the password
}
```
Response:

```JSON
{
   "code":0,
   "msg":"ok",
   "data":{
      "token":"4cccd33c-98b5-4a54-8ea5-c641a5fe396d"      // the token, expired after 2 hours
   }
}
```

### Invalidate token
Path: /user/token/invalidate
Request:
```JSON
{
   "token":"4cccd33c-98b5-4a54-8ea5-c641a5fe396d"           // the token to be invalidated
}
```
Response:

```JSON
{
   "code":0,
   "msg":"ok",
   "data":null
}

```

### Check user role
Path: /user/role/check
Request:
```JSON
{
   "token":"9e14a10d-9085-4c70-8467-128c6d802a8c",           // the token
   "role_name":"user"                                        // the role name
}
```
Response:

```JSON
{
   "code":0,
   "msg":"ok",
   "data":{
      "hasRole":false                                       // if the user has the role
   }
}

```

### List all roles of a user 
Path: /user/role/list
Request:
```JSON
{
   "token":"9e14a10d-9085-4c70-8467-128c6d802a8c"           // the token
}
```
Response:

```JSON
{
   "code":0,
   "msg":"ok",
   "data":{
      "roles":[                                             // the role list of the user
         "user"
      ] 
   }
}
```

## TBD
* some operations should be privileged, only allow admin to call them. such as
  1. create user (by user or by admin. If by user, should do some verification)
  2. delete user
  3. create role
  4. delete role
  5. add role to user
  
  this code is only for demonstration, so I don't do this.

* in a production environment, we'd better add a rate limiter for the APIs

* in a production environment, we should consider using a database instead of saving all data in memory.
