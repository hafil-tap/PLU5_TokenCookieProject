register → Create user {email, password, firstName}
- POST /login → Get JWT cookie
- POST /logout → Clear cookie

### Protected (login required)
- GET /profile → Current user info
- GET /tasks → User’s own tasks
- POST /tasks → Create new task {title, description}
- DELETE /tasks/:id → Delete own task

### Admin only
- GET /admin/users → List all users
- GET /admin/tasks → List all tasks

---

## Authentication Flow
1. /login checks credentials, signs JWT
2. JWT stored in HTTP-only cookie (auth_token)
3. Middleware verifies cookie token on protected routes
4. /logout clears the cookie

---

