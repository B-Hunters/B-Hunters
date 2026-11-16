"""The artefact a task publishes outlives the collector.

The Karton collector removes every object in the bucket that no
registered task references.  A raw write is referenced by nobody, so it
is removed within one collection interval — which is why the scanners
that download the crawler's URL list stopped producing findings.

These tests copy the collector's own decision out of Karton v5.5.0
(``karton/system/system.py``, ``gc_collect_resources``) and run it
against a task the platform published.
"""

from __future__ import annotations

from karton.core.resource import RemoteResource
from karton.core.task import Task

from b_hunters.artifacts import artifact_key, attach_artifact, publish_with_artifact


def _objects_the_collector_removes(object_uids, tasks, bucket):
    """The collector's decision, copied from Karton v5.5.0.

    The collector lists the object identifiers of the bucket — the keys,
    as strings — and removes every one that no task references.
    """
    to_remove = set(object_uids)
    for task in tasks:
        for resource in task.iterate_resources():
            if resource.bucket == bucket and resource.uid in to_remove:
                to_remove.remove(resource.uid)
    return to_remove


class _RecordingBackend:
    """A backend that records what was uploaded."""

    def __init__(self) -> None:
        self.uploaded: dict[tuple[str, str], bytes] = {}

    def upload_object(self, bucket, object_uid, content) -> None:
        self.uploaded[(bucket, object_uid)] = content

    def list_objects(self, bucket) -> list[str]:
        """The object identifiers of a bucket, as Karton lists them."""
        return [uid for (stored_bucket, uid) in self.uploaded if stored_bucket == bucket]


def test_a_raw_write_is_removed_by_the_collector():
    """This is the bug: a task that does not carry the object."""
    backend = _RecordingBackend()
    backend.upload_object("bhunters", "katana_s1_example.com", b"http://a\n")

    task = Task({"type": "paths", "stage": "scan"})

    removed = _objects_the_collector_removes(
        backend.list_objects("bhunters"), [task], "bhunters"
    )

    assert removed == {"katana_s1_example.com"}


def test_a_task_that_carries_the_object_keeps_it():
    backend = _RecordingBackend()
    body = b"http://a\n"
    task = Task({"type": "paths", "stage": "scan"})

    publish_with_artifact(
        backend, task, bucket="bhunters", key="katana_s1_example.com", body=body
    )

    removed = _objects_the_collector_removes(
        backend.list_objects("bhunters"), [task], "bhunters"
    )

    assert removed == set()
    assert backend.uploaded[("bhunters", "katana_s1_example.com")] == body


def test_the_object_is_released_when_the_task_is_gone():
    backend = _RecordingBackend()
    task = Task({"type": "paths", "stage": "scan"})
    publish_with_artifact(
        backend, task, bucket="bhunters", key="katana_s1_example.com", body=b"x"
    )

    removed = _objects_the_collector_removes(
        backend.list_objects("bhunters"), [], "bhunters"
    )

    assert removed == {"katana_s1_example.com"}


def test_the_key_is_the_one_the_workers_compute():
    """The workers build the key from the source, the scan and the target.

    The target is stripped of its scheme and its trailing slash first,
    which is what the worker does before it names the artefact.
    """
    assert artifact_key("katana", "s1", "http://example.com/") == "katana_s1_example.com"
    assert artifact_key("platform", "s1", "https://example.com/app/") == "platform_s1_example.com_app"


def test_the_encoder_agrees_with_the_base_class():
    """A producer and a consumer have to name the artefact the same way.

    The base class is what the workers use.  If the two encoders drift,
    the producer writes to a key the consumer never reads, and the
    symptom is a scanner that finds nothing.
    """
    from b_hunters.artifacts import encode_filename
    from b_hunters.bhunter import BHunters

    for value in (
        "http://example.com/",
        "a/b\\c:d*e?f|g<h>i\"j",
        "x" * 300,
        "plain",
    ):
        assert encode_filename(value) == BHunters.encode_filename(None, value)


def test_the_resource_carries_the_key_and_the_bucket():
    task = Task({"type": "paths", "stage": "scan"})
    attach_artifact(task, bucket="bhunters", key="katana_s1_x", size=3)

    resources = list(task.iterate_resources())

    assert len(resources) == 1
    assert isinstance(resources[0], RemoteResource)
    assert resources[0].uid == "katana_s1_x"
    assert resources[0].bucket == "bhunters"
