# Service 1: User Management and Authentication

Implemented by Adam Yahya.

Service 1 creates and manages user accounts and issues the Bearer JWT that every
other service checks. It uses the shared SQLite database. Passwords are stored
only as hashes and are never returned. Logins, account changes and refused
requests are written to the audit log (Service 5).

## Run

From the project root with the virtual environment active:

```bash
python -m database.init_db
python -m user_service.app        # port 5001
```

Base URL: `http://127.0.0.1:5001`. Log in with `POST /users/login/AdamYahya`, then
send `Authorization: Bearer <token>` with the protected requests. Tokens last
60 minutes.

## Responses

Success: `{"status": "success", "message": "...", "data": ...}`.
Error: `{"status": "error", "message": "..."}` with the HTTP status code below.

## Endpoints and access

| API | Method and path | Admin | Auditor | Analyst | Regular User | Success |
|---|---|---|---|---|---|---|
| Register User | POST /users/register/AdamYahya | any role | no token needed, Regular User only | same | same | 201 |
| Login | POST /users/login/AdamYahya | public | public | public | public | 200 |
| Get All Users | GET /users/AdamYahya | yes | yes | no | no | 200 |
| Get User by Username | GET /users/{username}/AdamYahya | any user | any user | no | own record only | 200 |
| Update User | PUT /users/{user_id}/AdamYahya | any user | no | no | own record only | 200 |
| Delete User | DELETE /users/{user_id}/AdamYahya | yes | no | no | no | 200 |

## User record

| Field | Description |
|---|---|
| user_id | Generated ID |
| full_name | Full name (max 100 characters) |
| username | Unique, 3 to 30 characters, starts with a letter, then letters, digits, `.`, `_` or `-` |
| email | Unique, stored in lower case |
| department | Department (max 100 characters) |
| role | `Security Administrator`, `Security Analyst`, `Regular User` or `Auditor` |
| account_status | `Active`, `Inactive` or `Suspended` (only `Active` accounts can log in) |
| created_at | Creation time (UTC), set by the system |
| last_login | Time of the last successful login, `null` until the first one |

Password rules: 8 to 128 characters with an uppercase letter, a lowercase letter
and a digit.

## 1. Register User

- **Purpose:** create a new account.
- **Method and endpoint:** `POST /users/register/AdamYahya`
- **Access:** public for the `Regular User` role (the default). Creating any other
  role needs a Security Administrator token.
- **Parameters:** none.

Request body:

| Field | Required | Notes |
|---|---|---|
| full_name, username, email, password, department | yes | rules above |
| role | no | one of the four roles, default `Regular User` |

```json
{
  "full_name": "Adam Yahya",
  "username": "AdamYahya",
  "email": "adam@example.com",
  "password": "Passw0rdOk",
  "department": "IT"
}
```

Response `201`:

```json
{
  "data": {
    "account_status": "Active",
    "created_at": "2026-10-17 19:30:00",
    "department": "IT",
    "email": "adam@example.com",
    "full_name": "Adam Yahya",
    "last_login": null,
    "role": "Regular User",
    "user_id": 4,
    "username": "AdamYahya"
  },
  "message": "User registered successfully",
  "status": "success"
}
```

| Status | When | Message |
|---|---|---|
| 400 | Missing, unknown or invalid field | `Missing required fields: email` / `email format is invalid` / `password must contain a digit` |
| 401 | Privileged role requested without a valid token | `Authentication required: send 'Authorization: Bearer <token>'` |
| 403 | Privileged role requested by a non-administrator | `Only a Security Administrator can create this role` |
| 409 | Username or email already used | `Username already exists` / `Email is already registered` |

## 2. Login

- **Purpose:** check the credentials and return a JWT.
- **Method and endpoint:** `POST /users/login/AdamYahya`
- **Access:** public.
- **Parameters:** none.

Request body: `password` plus either `username` or `email`.

```json
{ "username": "AdamYahya", "password": "Passw0rdOk" }
```

Response `200`:

```json
{
  "data": {
    "token": "<jwt>",
    "token_type": "Bearer",
    "user": {
      "account_status": "Active",
      "created_at": "2026-10-17 19:30:00",
      "department": "IT",
      "email": "adam@example.com",
      "full_name": "Adam Yahya",
      "last_login": "2026-10-17 19:31:12",
      "role": "Regular User",
      "user_id": 4,
      "username": "AdamYahya"
    }
  },
  "message": "Login successful",
  "status": "success"
}
```

| Status | When | Message |
|---|---|---|
| 400 | No username or email, missing password, unknown field | `Provide a username or an email` |
| 401 | Unknown user or wrong password (same answer for both) | `Invalid username or password` |
| 403 | Account is Inactive or Suspended | `Account is suspended` |

Every attempt is logged: `Successful login` (Information) or `Failed login` (Warning).

## 3. Get All Users

- **Purpose:** list every registered user.
- **Method and endpoint:** `GET /users/AdamYahya`
- **Access:** Security Administrator, Auditor.
- **Parameters:** none. No request body.

Response `200`: `data` is a list of user records (as above), ordered by `user_id`,
message `Users retrieved successfully`.

| Status | When | Message |
|---|---|---|
| 401 | No, invalid or expired token | `Invalid authentication token` |
| 403 | Analyst or Regular User | `User does not have permission to perform this operation` |

## 4. Get User by Username

- **Purpose:** return one user.
- **Method and endpoint:** `GET /users/{username}/AdamYahya`
- **Access:** Administrator and Auditor can view anyone. A Regular User can view
  only their own record. Analysts have no access.
- **Parameters:** `username` in the URL (not case sensitive). No request body.

Response `200`: `data` is one user record, message `User retrieved successfully`.

| Status | When | Message |
|---|---|---|
| 401 | No, invalid or expired token | `Authentication required: send 'Authorization: Bearer <token>'` |
| 403 | Analyst | `User does not have permission to perform this operation` |
| 403 | Regular User asking for someone else (or a name that does not exist, so names cannot be probed) | `You can only view your own user information` |
| 404 | Administrator or Auditor asks for an unknown username | `User not found` |

## 5. Update User

- **Purpose:** change a user's name, email or department.
- **Method and endpoint:** `PUT /users/{user_id}/AdamYahya`
- **Access:** Security Administrator (anyone), Regular User (own record only).
- **Parameters:** `user_id` in the URL, a positive whole number.

Request body: at least one of `full_name`, `email`, `department`. Role, username,
password and status cannot be changed here.

```json
{ "department": "Finance" }
```

Response `200`: `data` is the updated user record, message `User updated successfully`.

| Status | When | Message |
|---|---|---|
| 400 | Bad id, empty body, unknown field, invalid value | `user id must be a positive whole number` / `Unknown fields: role` |
| 401 | No, invalid or expired token | `Invalid authentication token` |
| 403 | Auditor or Analyst | `User does not have permission to perform this operation` |
| 403 | Regular User updating someone else | `You can only update your own user information` |
| 404 | No such user | `User not found` |
| 409 | New email belongs to another user | `Email is already registered` |

## 6. Delete User

- **Purpose:** remove an account.
- **Method and endpoint:** `DELETE /users/{user_id}/AdamYahya`
- **Access:** Security Administrator only.
- **Parameters:** `user_id` in the URL. No request body.

Response `200`:

```json
{ "message": "User deleted successfully", "status": "success", "data": null }
```

| Status | When | Message |
|---|---|---|
| 400 | Bad id, or the administrator deletes their own account | `You cannot delete your own account` |
| 401 | No, invalid or expired token | `Invalid authentication token` |
| 403 | Not an administrator | `User does not have permission to perform this operation` |
| 404 | No such user | `User not found` |
| 409 | The user still owns assets, incidents or other records | `User is still referenced by assets, incidents or other records and cannot be deleted` |

## How the main APIs work

**Login.** The service looks the user up by username or email and compares the
password with the stored hash. An unknown user and a wrong password give the
same `401`, so an attacker cannot tell which usernames exist. On success it
updates `last_login`, writes a `Successful login` log and signs a JWT whose
subject is the user id. Services 2 to 9 only accept this token.

**Register User.** All fields are validated before anything is saved (email
format, password strength, unique username and email). The role defaults to
Regular User, which anyone may create. Asking for a higher role makes the
service check the token, so nobody can give themselves administrator rights.

**Get User by Username.** Access depends on the caller as well as the role: a
Regular User may only read their own record. A request for another user, or for
a name that does not exist, gets the same `403`, so the API cannot be used to
find out which usernames exist.

## Tests

Every route and role is covered by the Postman folder **Service 1 – Users** in
`postman/Security Incident System.postman_collection.json`. Screenshots are in
`screenshots/service1/`.
