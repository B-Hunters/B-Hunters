"""The comments on an issue.

A finding is evidence.  A comment is what the operator says about it:
why it matters, why it was dismissed, what is being done.

There is one user, and a comment is still editable only by its author.
The guarantee is worth having because it is what makes the record
trustworthy: a comment that anybody could change is a comment that says
nothing.
"""

from __future__ import annotations

from typing import Any, Optional

from .client import Database
from .repositories import new_id, utcnow


class CommentRepository:
    """The comments an operator left on the issues."""

    def __init__(self, db: Database) -> None:
        self._db = db

    @property
    def _col(self):
        return self._db.collection("platform_issue_comments")

    def add(
        self,
        *,
        issue_id: str,
        scan_id: str = "",
        finding_id: str = "",
        author: str,
        body: str,
    ) -> dict[str, Any]:
        """Add a comment to an issue."""
        text = (body or "").strip()
        if not text:
            raise ValueError("a comment cannot be empty")
        now = utcnow()
        document: dict[str, Any] = {
            "comment_id": new_id(),
            "issue_id": issue_id,
            "scan_id": scan_id,
            "finding_id": finding_id,
            "author": author or "anonymous",
            "body": text,
            "created_at": now,
            "updated_at": now,
        }
        self._col.insert_one(document)
        return document

    def get(self, comment_id: str) -> Optional[dict[str, Any]]:
        """Return one comment."""
        return self._col.find_one({"comment_id": comment_id})

    def list_for_issue(self, issue_id: str) -> list[dict[str, Any]]:
        """The comments of an issue, oldest first."""
        return list(self._col.find({"issue_id": issue_id}).sort("created_at", 1))

    def edit(self, comment_id: str, *, author: str, body: str) -> bool:
        """Edit a comment.  Only its author may."""
        text = (body or "").strip()
        if not text:
            raise ValueError("a comment cannot be empty")
        result = self._col.update_one(
            {"comment_id": comment_id, "author": author},
            {"$set": {"body": text, "updated_at": utcnow()}},
        )
        return result.matched_count > 0

    def delete(self, comment_id: str, *, author: str) -> bool:
        """Delete a comment.  Only its author may."""
        result = self._col.delete_one({"comment_id": comment_id, "author": author})
        return result.deleted_count > 0
