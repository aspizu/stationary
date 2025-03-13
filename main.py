from __future__ import annotations

import base64
import contextlib
import hashlib
import hmac
import json
import re
import sqlite3
import time
import urllib.parse
from dataclasses import dataclass, field
from datetime import UTC, datetime
from http import HTTPMethod, HTTPStatus
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from string import Template
from typing import Any, Protocol, final, override

SECRET_KEY = "my_secret_key"  # Keep this safe!


def format_distance_to_now(instance: datetime) -> str:
    right = datetime.now(tz=UTC).timestamp()
    left = instance.timestamp()
    distance = right - left
    if distance < 30:
        return "less than a minute ago"
    if distance < 1 * 60 + 30:
        return "a minute ago"
    if distance < 144 * 60 + 30:
        minutes = round(distance / 60)
        return f"{minutes} minutes ago"
    if distance < 89 * 60 + 30:
        return "about an hour ago"
    if distance < 23 * 60 * 60 + 59 * 60 + 30:
        hours = round(distance / 3600)
        return f"about {hours} hours ago"
    if distance < 41 * 60 * 60 + 59 * 60 + 30:
        return "a day ago"
    if distance < 29 * 24 * 60 * 60 + 23 * 60 * 60 + 59 * 60 + 30:
        days = round(distance / (24 * 60 * 60))
        return f"{days} days ago"
    if distance < 44 * 24 * 60 * 60 + 23 * 60 * 60 + 59 * 60 + 30:
        return "about a month ago"
    if distance < 59 * 24 * 60 * 60 + 23 * 60 * 60 + 59 * 60 + 30:
        return "about 2 months ago"
    if distance < 31_536_000:
        months = round(distance / (30 * 24 * 60 * 60))
        return f"{months} months ago"
    if distance < 31_536_000 + 3 * 30 * 24 * 60 * 60:
        return "about a year ago"
    if distance < 31_536_000 + 9 * 30 * 24 * 60 * 60:
        return "over a year ago"
    if distance < 31_536_000 * 2:
        return "almost 2 years ago"
    return "a really fucking long time ago"


def create_token(data: object, expiry: int = 3600) -> str:
    """Creates a signed token with an expiry time (default 1 hour)."""
    data_str = str(data)
    expiration = int(time.time()) + expiry
    # Build the payload as a string
    payload = f"{data_str}:{expiration}"
    # Use hex encoding for the signature
    signature = hmac.new(
        SECRET_KEY.encode(), payload.encode(), hashlib.sha256
    ).hexdigest()
    # Create a token string: note that data may include colons, so we use the last two parts for expiration and signature
    token_str = f"{data_str}:{expiration}:{signature}"
    # Encode the whole token in URL-safe base64
    return base64.urlsafe_b64encode(token_str.encode()).decode()


def verify_token(token: str) -> tuple[bool, str]:
    """Verifies the token and checks if it's expired."""
    try:
        # Decode the token from base64
        decoded = base64.urlsafe_b64decode(token).decode()
        # Split the token by colon. Since the data can contain colons, we take the last two as expiration and signature.
        parts = decoded.split(":")
        if len(parts) < 3:
            return False, "Invalid token format"

        # Extract expiration and signature from the end
        expiration_str = parts[-2]
        provided_signature = parts[-1]
        # The remaining parts form the original data
        data_str = ":".join(parts[:-2])
        expiration = int(expiration_str)

        # Check if the token has expired
        if time.time() > expiration:
            return False, "Token expired"

        # Rebuild the payload and compute the expected signature
        payload = f"{data_str}:{expiration_str}"
        expected_signature = hmac.new(
            SECRET_KEY.encode(), payload.encode(), hashlib.sha256
        ).hexdigest()

        # Securely compare the signatures
        if hmac.compare_digest(provided_signature, expected_signature):
            return True, data_str
        return False, "Invalid signature"
    except Exception as e:
        return False, f"Error verifying token: {e}"


@final
class Row:
    """Represents a row in the database."""

    def __init__(
        self,
        cursor: sqlite3.Cursor,
        row: tuple[int | float | str | bytes | None, ...],
    ) -> None:
        """Initialize the Row object.

        Args:
        ----
            cursor: The database cursor.
            row: The row data.

        """
        fields = [column[0] for column in cursor.description]
        self.dict__ = dict(zip(fields, row))

    def __getattr__(self, key: str) -> Any:
        """Get attribute value by key.

        Args:
        ----
            key: The attribute key.

        Returns: The attribute value.

        Raises:
        ------
            AttributeError: If the attribute key is not found.

        """
        if key == "__dict__":
            return self.dict__
        try:
            return self.dict__[key]
        except KeyError:
            raise AttributeError(key) from None

    @override
    def __repr__(self) -> str:
        """Return a string representation of the Row object."""
        return repr(self.dict__)

    @override
    def __str__(self) -> str:
        """Return a string representation of the Row object."""
        return str(self.dict__)


def db() -> tuple[sqlite3.Connection, sqlite3.Cursor]:
    """Connect to the database and return the connection and cursor objects.

    Returns: The connection and cursor objects.
    """
    con = sqlite3.connect("database.sqlite3")
    con.row_factory = Row
    con.executescript(
        """
        PRAGMA foreign_keys = ON;
        PRAGMA journal_mode = WAL;
        PRAGMA synchronous = normal;
        PRAGMA journal_size_limit = 6144000;
        """
    )
    return con, con.cursor()


class ResponseProtocol(Protocol):
    def send(self, handler: SimpleHTTPRequestHandler) -> None: ...


@dataclass
class Response:
    status: HTTPStatus = HTTPStatus.OK
    headers: dict[str, str] = field(default_factory=dict)
    set_session: str | None = None
    remove_session: bool = False
    body: bytes = b""

    def send(self, handler: SimpleHTTPRequestHandler) -> None:
        if "content-type" not in self.headers:
            self.headers["content-type"] = "text/html"
        handler.send_response(self.status.value)
        if self.set_session is not None:
            self.headers["Set-Cookie"] = f"session={
                create_token(self.set_session)
            }; HttpOnly; Secure; SameSite=Strict"
        if self.remove_session:
            self.headers["Set-Cookie"] = "session=; HttpOnly; Secure; SameSite=Strict"
        for key, value in self.headers.items():
            handler.send_header(key, value)
        handler.end_headers()
        handler.wfile.write(self.body)


def render_template(
    template: str, mapping: dict[str, object], layout: str | None = None
) -> str:
    if layout:
        layout = Path(layout).read_text()
    text = Path(template).read_text()
    if layout:
        text = layout.replace("<!-- SLOT -->\n", text)
    lines = text.splitlines()
    outlines = []
    i = 0
    stack = []

    while i < len(lines):
        line = lines[i]
        if line.startswith("<!-- IF "):
            key = line.removeprefix("<!-- IF ").removesuffix(" -->")
            invert = False
            if key.startswith("NOT "):
                key = key.removeprefix("NOT ")
                invert = True
            condition_met = bool(mapping.get(key)) != invert
            stack.append(condition_met)
        elif line.startswith("<!-- ENDIF -->"):
            if stack:
                stack.pop()
        elif all(stack):  # Only add lines if all conditions in the stack are met
            outlines.append(line)
        i += 1

    return Template("\n".join(outlines)).substitute(mapping)


@dataclass
class TemplateResponse:
    path: str
    layout: str = "templates/layout.html"
    status: HTTPStatus = HTTPStatus.OK
    headers: dict[str, str] = field(default_factory=dict)
    mapping: dict[str, object] = field(default_factory=dict)

    def send(self, handler: SimpleHTTPRequestHandler) -> None:
        Response(
            status=self.status,
            headers=self.headers,
            body=render_template(self.path, self.mapping, self.layout).encode(),
        ).send(handler)


@dataclass
class Request:
    handler: SimpleHTTPRequestHandler
    method: HTTPMethod = HTTPMethod.GET

    def form(self) -> dict[str, str]:
        content_length = int(self.handler.headers.get("Content-Length", 0))
        if content_length == 0:
            return {}
        raw_data = self.handler.rfile.read(content_length).decode("utf-8")
        return dict(urllib.parse.parse_qsl(raw_data, keep_blank_values=True))

    def session(self) -> dict[str, Any] | None:
        if cookies := self.handler.headers.get("Cookie"):
            for cookie in cookies.split(";"):
                if cookie.startswith("session="):
                    token = cookie.removeprefix("session=")
                    valid, data = verify_token(token)
                    if valid:
                        return json.loads(data)
                    print(f"{data}: {token}")
        return None


def index(request: Request) -> ResponseProtocol:
    session = request.session()
    username = session and session.get("username")
    _, cur = db()
    cur.execute(
        """
        SELECT (
            select count(*) from reply where reply.log_id = log.id
        ) as replies, (
            select count(*) from thumbs where thumbs.log_id = log.id
        ) as thumbs, log.id as pid, username, content, log.created_at
        FROM log JOIN account ON log.author_id = account.id
        ORDER BY log.created_at DESC
        """
    )
    rows = cur.fetchall()
    return TemplateResponse(
        "templates/index.html",
        mapping={
            "title": f"Hey {username}" if username else "Station",
            "username": username,
            "logs": "".join(
                render_template(
                    "templates/log.html",
                    {
                        **row.dict__,
                        "created_at": format_distance_to_now(
                            datetime.fromtimestamp(row.created_at, tz=UTC)
                        ),
                    },
                )
                for row in rows
            ),
        },
    )


USERNAME_MINLENGTH = 3
USERNAME_MAXLENGTH = 16
USERNAME_PATTERN = re.compile(r"[a-zA-Z0-9\-_]+")
PASSWORD_MINLENGTH = 8
CONTENT_MINLENGTH = 1
CONTENT_MAXLENGTH = 500


def join(request: Request) -> ResponseProtocol:
    error = None
    if request.method == HTTPMethod.POST:
        form = request.form()
        username = form.get("username")
        password = form.get("password")
        if (
            not username
            or not password
            or len(username) < USERNAME_MINLENGTH
            or len(username) > USERNAME_MAXLENGTH
            or len(password) < PASSWORD_MINLENGTH
            or not USERNAME_PATTERN.fullmatch(username)
        ):
            return Response(status=HTTPStatus.BAD_REQUEST)
        conn, cur = db()
        cur.execute("SELECT * FROM account WHERE username = ?", [username])
        if cur.fetchone():
            error = "Username already exists"
        else:
            cur.execute(
                "INSERT INTO account (username, password_hash) VALUES (?, ?)",
                [username, hashlib.blake2b(password.encode()).hexdigest()],
            )
            cur.execute("SELECT last_insert_rowid() as id")
            row = cur.fetchone()
            conn.commit()
            return Response(
                status=HTTPStatus.FOUND,
                headers={"Location": "/"},
                set_session=json.dumps({"username": username, "userid": row.id}),
            )
    return TemplateResponse(
        "templates/join.html",
        mapping={
            "title": "Join Station",
            "error": error,
            "USERNAME_MINLENGTH": USERNAME_MINLENGTH,
            "USERNAME_MAXLENGTH": USERNAME_MAXLENGTH,
            "USERNAME_PATTERN": USERNAME_PATTERN.pattern,
            "PASSWORD_MINLENGTH": PASSWORD_MINLENGTH,
        },
    )


def login(request: Request) -> ResponseProtocol:
    error = None
    if request.method == HTTPMethod.POST:
        form = request.form()
        username = form.get("username")
        password = form.get("password")
        if (
            not username
            or not password
            or len(username) < USERNAME_MINLENGTH
            or len(username) > USERNAME_MAXLENGTH
            or len(password) < PASSWORD_MINLENGTH
            or not USERNAME_PATTERN.fullmatch(username)
        ):
            return Response(status=HTTPStatus.BAD_REQUEST)
        _, cur = db()
        cur.execute(
            "SELECT id, password_hash FROM account WHERE username = ?",
            [username],
        )
        row = cur.fetchone()
        if (
            not row
            or row.password_hash != hashlib.blake2b(password.encode()).hexdigest()
        ):
            error = "Invalid username or password"
        else:
            return Response(
                status=HTTPStatus.FOUND,
                headers={"Location": "/"},
                set_session=json.dumps({"username": username, "userid": row.id}),
            )
    return TemplateResponse(
        "templates/login.html",
        mapping={
            "title": "Login",
            "error": error,
            "USERNAME_MINLENGTH": USERNAME_MINLENGTH,
            "USERNAME_MAXLENGTH": USERNAME_MAXLENGTH,
            "USERNAME_PATTERN": USERNAME_PATTERN.pattern,
            "PASSWORD_MINLENGTH": PASSWORD_MINLENGTH,
        },
    )


def logout(_request: Request) -> ResponseProtocol:
    return Response(
        status=HTTPStatus.FOUND, headers={"Location": "/"}, remove_session=True
    )


def post(request: Request) -> ResponseProtocol:
    session = request.session()
    if not session:
        return Response(status=HTTPStatus.UNAUTHORIZED)
    if request.method == HTTPMethod.POST:
        form = request.form()
        content = form.get("content")
        if (
            not content
            or len(content) < CONTENT_MINLENGTH
            or len(content) > CONTENT_MAXLENGTH
        ):
            return Response(status=HTTPStatus.BAD_REQUEST)
        conn, cur = db()
        cur.execute(
            "INSERT INTO log (author_id, content) VALUES (?, ?)",
            [session["userid"], content],
        )
        conn.commit()
        cur.execute("SELECT last_insert_rowid() as id")
        row = cur.fetchone()
        return Response(
            status=HTTPStatus.FOUND,
            headers={"Location": f"/post/{row.id}"},
        )
    return TemplateResponse(
        "templates/post.html",
        mapping={
            "title": "Enter log",
            "CONTENT_MINLENGTH": CONTENT_MINLENGTH,
            "CONTENT_MAXLENGTH": CONTENT_MAXLENGTH,
        },
    )


def getpost(request: Request, _pid: str) -> ResponseProtocol:
    try:
        pid = int(_pid)
    except ValueError:
        return Response(status=HTTPStatus.NOT_FOUND)
    conn, cur = db()
    session = request.session()
    if request.method == HTTPMethod.POST:
        if not session:
            return Response(status=HTTPStatus.UNAUTHORIZED)
        form = request.form()
        content = form.get("content")
        if (
            not content
            or len(content) < CONTENT_MINLENGTH
            or len(content) > CONTENT_MAXLENGTH
        ):
            return Response(status=HTTPStatus.BAD_REQUEST)
        cur.execute(
            "INSERT INTO reply (author_id, log_id, content) VALUES (?, ?, ?)",
            [session["userid"], pid, content],
        )
        conn.commit()
    is_liked = False
    if session:
        cur.execute(
            "SELECT true FROM thumbs WHERE liker_id = ? AND log_id = ?",
            [session["userid"], pid],
        )
        is_liked = cur.fetchone()
    cur.execute(
        "SELECT * FROM log JOIN account ON author_id = account.id WHERE log.id = ?",
        [pid],
    )
    row = cur.fetchone()
    if not row:
        return Response(status=HTTPStatus.NOT_FOUND)
    cur.execute(
        """
        SELECT * FROM reply JOIN account ON author_id = account.id WHERE log_id = ?
        ORDER BY reply.created_at DESC
        """,
        [pid],
    )
    rows = cur.fetchall()
    cur.execute("SELECT COUNT(*) as c FROM thumbs WHERE log_id = ?", [pid])
    likecount = cur.fetchone()
    likecount = likecount.c if likecount else 0
    cur.execute(
        """
        SELECT username FROM thumbs JOIN account ON liker_id = account.id
        WHERE log_id = ? LIMIT 4
        """,
        [pid],
    )
    likedby = ", ".join(row.username for row in cur.fetchall())
    if likecount > 4:
        likedby += f" and {likecount - 4} others"
    if likecount > 0:
        likedby = "liked by " + likedby
    return TemplateResponse(
        "templates/getpost.html",
        mapping={
            "title": row.username,
            **row.dict__,
            "CONTENT_MINLENGTH": CONTENT_MINLENGTH,
            "CONTENT_MAXLENGTH": CONTENT_MAXLENGTH,
            "replycount": len(rows),
            "is_liked": is_liked,
            "likedby": likedby,
            "session": session,
            "replies": "".join(
                render_template(
                    "templates/reply.html",
                    {
                        **row.dict__,
                        "created_at": format_distance_to_now(
                            datetime.fromtimestamp(row.created_at, tz=UTC)
                        ),
                    },
                )
                for row in rows
            ),
        },
    )


def user(request: Request, user: Row) -> ResponseProtocol:
    session = request.session()
    _, cur = db()
    cur.execute(
        """
        SELECT (SELECT COUNT(*) FROM follow WHERE following_id = ?) as followers,
               (SELECT COUNT(*) FROM follow WHERE follower_id = ?) as following
        """,
        [user.id, user.id],
    )
    follow = cur.fetchone()
    is_following = False
    if session:
        cur.execute(
            """
            SELECT true FROM follow WHERE follower_id = ? AND following_id = ?
            """,
            [session["userid"], user.id],
        )
        is_following = cur.fetchone()
    cur.execute(
        """
        SELECT *, (
            select count(*) from reply where reply.log_id = log.id
        ) as replies, (
            select count(*) from thumbs where thumbs.log_id = log.id
        ) as thumbs
        FROM log WHERE author_id = ?
        ORDER BY log.created_at DESC
        """,
        [user.id],
    )
    rows = cur.fetchall()
    if request.method == HTTPMethod.POST:
        form = request.form()
        bio = form.get("bio")
        location = form.get("location")
        image = form.get("image")
        link = form.get("link")
        sql = ""
        params = []
        if bio:
            sql += ", bio = ?"
            params.append(bio)
            user.dict__["bio"] = bio
        if location:
            sql += ", location = ?"
            params.append(location)
            user.dict__["location"] = location
        if image:
            sql += ", image = ?"
            params.append(image)
            user.dict__["image"] = image
        if link:
            sql += ", link = ?"
            params.append(link)
            user.dict__["link"] = link
        if sql:
            conn, cur = db()
            sql = f"""
            UPDATE account
            SET {sql[2:]}
            WHERE id = ?
            """  # noqa: S608
            cur.execute(sql, (*params, user.id))
            conn.commit()
    return TemplateResponse(
        "templates/user.html",
        mapping={
            "title": user.username,
            **user.dict__,
            **follow.dict__,
            "show_follow_btn": session and session["userid"] != user.id,
            "session": session and session["userid"] == user.id,
            "is_following": is_following,
            "logs": "".join(
                render_template(
                    "templates/log.html",
                    {
                        **user.dict__,
                        **row.dict__,
                        "pid": row.id,
                        "created_at": format_distance_to_now(
                            datetime.fromtimestamp(row.created_at, tz=UTC)
                        ),
                    },
                )
                for row in rows
            ),
        },
    )


def follow(request: Request, username: str) -> ResponseProtocol:
    if not (session := request.session()):
        return Response(HTTPStatus.UNAUTHORIZED)
    with contextlib.suppress(sqlite3.DatabaseError):
        conn, cur = db()
        cur.execute(
            """
        INSERT INTO follow (follower_id, following_id)
        VALUES (?, (SELECT id FROM account WHERE username = ?))
        """,
            [session["userid"], username],
        )
        conn.commit()
    return Response(HTTPStatus.FOUND, {"Location": f"/{username}"})


def unfollow(request: Request, username: str) -> ResponseProtocol:
    if not (session := request.session()):
        return Response(HTTPStatus.UNAUTHORIZED)
    with contextlib.suppress(sqlite3.DatabaseError):
        conn, cur = db()
        cur.execute(
            """
        DELETE FROM follow WHERE follower_id = ? AND following_id = (
            SELECT id FROM account WHERE username = ?
        )
        """,
            [session["userid"], username],
        )
        conn.commit()
    return Response(HTTPStatus.FOUND, {"Location": f"/{username}"})


def like(request: Request, pid: str) -> ResponseProtocol:
    if not (session := request.session()):
        return Response(HTTPStatus.UNAUTHORIZED)
    with contextlib.suppress(sqlite3.DatabaseError):
        conn, cur = db()
        cur.execute(
            "INSERT INTO thumbs (liker_id, log_id) VALUES (?, ?)",
            [session["userid"], pid],
        )
        conn.commit()
    return Response(HTTPStatus.FOUND, {"Location": f"/post/{pid}"})


def unlike(request: Request, pid: str) -> ResponseProtocol:
    if not (session := request.session()):
        return Response(HTTPStatus.UNAUTHORIZED)
    with contextlib.suppress(sqlite3.DatabaseError):
        conn, cur = db()
        cur.execute(
            "DELETE FROM thumbs WHERE liker_id = ? AND log_id = ?",
            [session["userid"], pid],
        )
        conn.commit()
    return Response(HTTPStatus.FOUND, {"Location": f"/post/{pid}"})


class RequestHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs, directory="static")

    @override
    def do_GET(self) -> None:
        self.router(Request(self))

    def router(self, request: Request) -> None:
        url = urllib.parse.urlparse(self.path)
        if route := {
            "/": index,
            "/join": join,
            "/login": login,
            "/logout": logout,
            "/post": post,
        }.get(url.path):
            route(request).send(self)
            return
        if url.path.startswith("/post/"):
            getpost(request, url.path.removeprefix("/post/")).send(self)
            return
        if url.path.startswith("/follow/"):
            follow(request, url.path.removeprefix("/follow/")).send(self)
            return
        if url.path.startswith("/unfollow/"):
            unfollow(request, url.path.removeprefix("/unfollow/")).send(self)
            return
        if url.path.startswith("/like/"):
            like(request, url.path.removeprefix("/like/")).send(self)
            return
        if url.path.startswith("/unlike/"):
            unlike(request, url.path.removeprefix("/unlike/")).send(self)
            return
        _, cur = db()
        cur.execute(
            "SELECT * FROM account WHERE username = ?", [url.path.removeprefix("/")]
        )
        row = cur.fetchone()
        if row:
            user(request, row).send(self)
            return
        super().do_GET()

    def do_POST(self) -> None:
        self.router(Request(self, method=HTTPMethod.POST))


def main() -> None:
    server_address = ("127.0.0.1", 8000)
    httpd = ThreadingHTTPServer(server_address, RequestHandler)

    try:
        print(f"Serving at http://{server_address[0]}:{server_address[1]}/")
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("Shutting down...")
        httpd.server_close()


if __name__ == "__main__":
    main()
