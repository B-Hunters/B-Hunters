"""The artefact a task publishes.

Karton keeps an object in the object store for exactly as long as a
registered task references it.  The collector removes every object that no
task references, so a raw write disappears within one collection interval
and the consumers that were meant to read it find nothing.

An artefact is therefore attached to the task that publishes it, as a
Karton resource.  The consumers keep downloading it by the key they
already compute; only the lifetime of the object changes.
"""

from __future__ import annotations

import hashlib
import re

from karton.core.resource import RemoteResource
from karton.core.task import Task

#: The characters a worker replaces when it builds an artefact name.
_INVALID = re.compile(r'[<>:"/\\|?*]')

#: The scheme a worker strips from a target before it names an artefact.
_SCHEME = re.compile(r"^https?://")

#: The length a worker shortens an artefact name at.
_MAX_NAME = 255


def encode_filename(value: str) -> str:
    """The form a worker uses for an artefact name.

    This is the base class's ``encode_filename``, reproduced here so that
    a producer and a consumer agree without either importing the other.
    The two must agree exactly — including the shortening of a very long
    name — or the producer writes to a key the consumer never reads.
    """
    safe = _INVALID.sub("_", value)

    if len(safe) > _MAX_NAME:
        # The worker shortens the name for the filesystem, not as a
        # security control.
        safe = hashlib.md5(value.encode(), usedforsecurity=False).hexdigest()  # noqa: S324

    return safe


def artifact_key(source: str, scan_id: str, target: str) -> str:
    """The key a worker computes for the artefact it downloads.

    A worker builds it from the task's ``source`` payload, the scan
    identifier and the target, with the target stripped of its scheme
    and its trailing slash.  The producer has to agree, or the consumer
    will look for an object nobody wrote.
    """
    normalised = _SCHEME.sub("", target).rstrip("/")
    return f"{source}_{scan_id}_{encode_filename(normalised)}"


def attach_artifact(task: Task, *, bucket: str, key: str, size: int) -> Task:
    """Give the task the artefact its consumers will read.

    The resource is persistent, so it is inherited by every task in the
    subtree, and so the fork the router makes for each consumer carries
    it too.
    """
    resource = RemoteResource(name=key, bucket=bucket, uid=key, size=size)
    task.add_payload("artifact", resource, persistent=True)
    return task


def publish_with_artifact(
    backend, task: Task, *, bucket: str, key: str, body: bytes
) -> Task:
    """Upload the artefact and give the task the reference to it.

    The task has to be published *after* the upload and *with* the
    reference attached: the collector only keeps an object that a
    registered task names, and the task is registered when it is sent.
    """
    backend.upload_object(bucket, key, body)
    attach_artifact(task, bucket=bucket, key=key, size=len(body))
    return task
