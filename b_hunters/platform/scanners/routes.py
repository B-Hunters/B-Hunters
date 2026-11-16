"""The API routes a JavaScript bundle hides.

The REST surface of a single-page application is not a set of links a
crawler follows: the routes are strings inside the bundle.  A scanner
handed those routes can test them, and a report that lists them can say
what the application exposes.

The routes are found statically.  Nothing is executed, and nothing is
fetched: the bundle is text, and the routes are the paths in it.

A route is only useful to a scanner if it carries a parameter, because
the scanners filter their list with ``grep "="`` and
``uro --filter hasparams``.  A route without one is kept — it is still
part of the surface, and the report lists it — but it is written bare,
so the filter drops it and the scanner does not try to test a path it
cannot vary.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

#: A path that begins a route: a quoted string that starts with a slash.
#:
#: A template literal usually interpolates the host in front of the path:
#: ``${this.hostServer}/rest/products/search?q=${t}``.  The interpolation is
#: part of the route, so it is allowed here and stripped afterwards.
_PATH = re.compile(
    r"[\"'`]((?:\$\{[^}]{0,160}\})?/[A-Za-z0-9_\-./{}:$?=&%]{1,200})[\"'`]"
)

#: The parameters of a route, when the bundle writes them out.
_PARAM = re.compile(r"[?&]([A-Za-z_][A-Za-z0-9_]*)=")

#: An interpolated value in a template literal.
_INTERPOLATION = re.compile(r"\$\{[^}]{0,160}\}")

#: A method used as a call: ``axios.post(``, ``get(``, ``.delete(``.
_CALL_METHOD = re.compile(r"(?:\.|,|\(|\s)(get|post|put|patch|delete|head|options)\s*\(", re.I)

#: A method written in an options object: ``method: "POST"``.
_OPTION_METHOD = re.compile(r"method\s*:\s*[\"']([A-Za-z]+)[\"']", re.I)

#: The base a client is configured with: ``baseURL: "/rest"``.
_BASE = re.compile(
    r"(?:baseURL|base_url|baseUrl|apiUrl|api_url|API_URL|apiBase)\s*[:=]\s*[\"'`]([^\"'`]{1,200})[\"'`]"
)

#: A path that names a file is an asset, not a route.
_ASSET = re.compile(r"\.(js|mjs|css|png|jpe?g|gif|svg|woff2?|ico|map|html?|json|txt)$", re.I)


@dataclass(frozen=True)
class Route:
    """One API route a bundle names."""

    path: str
    method: str | None
    parameters: tuple[str, ...]

    @property
    def key(self) -> str:
        """The identity of the route, for de-duplication."""
        return f"{self.method or ''} {self.path}"


def _parameters(path: str) -> tuple[str, ...]:
    """The parameter names a path spells out."""
    return tuple(dict.fromkeys(_PARAM.findall(path)))


def _base_path(bundle: str) -> tuple[str, tuple[int, int]]:
    """The path a client is configured with, if it has one.

    A single-page application usually configures its client once -
    ``axios.create({baseURL: "/rest"})`` - and then calls it with
    relative paths.  The route a scanner should test is the join of the
    two.

    A base that is an absolute URL is not a path: it names another host,
    which the scope decides about, so it is not joined here.

    The span of the base is returned as well, so that the base itself is
    not mistaken for a route.
    """
    match = _BASE.search(bundle)
    if not match:
        return "", (-1, -1)

    base = match.group(1).strip()
    if not base.startswith("/") or base.startswith("//"):
        return "", (-1, -1)

    return base.rstrip("/"), match.span(1)


def _method_for(bundle: str, start: int, end: int) -> str | None:
    """The method a call uses, when the bundle names one.

    The text around the path is searched for a method used as a call -
    ``axios.post(`` - and for one written in an options object -
    ``method: "POST"``.
    """
    window = bundle[max(0, start - 120) : end + 200]

    option = _OPTION_METHOD.search(window)
    if option:
        return option.group(1).upper()

    call = _CALL_METHOD.search(window)
    if call:
        return call.group(1).upper()

    return None


def extract(bundle: str) -> list[Route]:
    """The API routes named in a JavaScript bundle.

    A path is taken when it is a quoted string that begins with a slash.
    The parameters are the ones written on the path itself - the ones in
    the text around it belong to other calls and are not this route's.
    The method is the one the call uses.  A path is joined to the base
    the client was configured with.
    """
    if not bundle:
        return []

    base, base_span = _base_path(bundle)
    routes: dict[str, Route] = {}

    for match in _PATH.finditer(bundle):
        path = match.group(1)

        if _ASSET.search(path):
            continue

        # The base itself is a configuration, not a route.
        if base_span[0] <= match.start(1) < base_span[1]:
            continue

        # An interpolated host means the path is already absolute.
        interpolated = path.startswith("${")

        # The parameters are the ones written on the path.
        parameters = _parameters(path)
        clean_path = _INTERPOLATION.sub("", path.split("?")[0]).rstrip("/") or path
        if not clean_path.startswith("/"):
            clean_path = "/" + clean_path

        # A path that still holds an interpolated value cannot be tested:
        # the value is only known at run time.
        if _INTERPOLATION.search(clean_path):
            continue

        # A protocol-relative path names another host.
        if clean_path.startswith("//"):
            continue

        if base and not interpolated and not clean_path.startswith(base):
            clean_path = f"{base}{clean_path}"

        route = Route(
            path=clean_path,
            method=_method_for(bundle, match.start(), match.end()),
            parameters=parameters,
        )
        routes.setdefault(route.key, route)

    return list(routes.values())


def as_urls(route: Route, base: str) -> list[str]:
    """The URLs a scanner can test for a route.

    A route with parameters is written with them, so the scanner's filter
    keeps it and can vary it.  A route without them is written bare.
    """
    origin = base.rstrip("/")
    url = f"{origin}{route.path}"

    if not route.parameters:
        return [url]

    query = "&".join(f"{name}=" for name in route.parameters)
    return [f"{url}?{query}"]
