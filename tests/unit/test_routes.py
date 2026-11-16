"""The routes a JavaScript bundle hides.

The REST routes of a single-page application are not links a crawler
follows: they are strings in the bundle.  A scanner handed those routes
can test them, and a report that lists them can say what the
application exposes.
"""

from __future__ import annotations

from b_hunters.platform.scanners.routes import Route, as_urls, extract


def test_a_route_in_the_bundle_is_found():
    bundle = """
    const api = axios.create({baseURL: "/rest"});
    api.get("/products/search?q=", params);
    api.post("/users", body);
    """

    routes = extract(bundle)

    assert ("/rest/products/search", ("q",)) in [(r.path, r.parameters) for r in routes]


def test_a_parameterless_route_is_found():
    bundle = 'fetch("/api/Challenges");'

    routes = extract(bundle)

    assert "/api/Challenges" in [r.path for r in routes]


def test_a_route_that_names_a_file_is_not_a_route():
    bundle = 'const x = "/static/app.js"; const y = "/api/orders";'

    routes = extract(bundle)

    assert [r.path for r in routes] == ["/api/orders"]


def test_the_method_is_taken_from_the_text_around_the_path():
    bundle = 'axios.post("/api/orders", body);'

    routes = extract(bundle)

    assert routes[0].method == "POST"


def test_a_route_is_turned_into_a_url_that_carries_its_parameters():
    route = Route(path="/rest/products/search", method="GET", parameters=("q",))

    urls = as_urls(route, "http://target:3000")

    assert urls == ["http://target:3000/rest/products/search?q="]


def test_a_route_with_no_parameters_is_still_usable():
    route = Route(path="/api/Challenges", method=None, parameters=())

    urls = as_urls(route, "http://target:3000")

    assert urls == ["http://target:3000/api/Challenges"]


def test_two_routes_with_the_same_path_are_one_route():
    bundle = 'get("/api/x"); post("/api/x");'

    routes = extract(bundle)

    assert len(routes) == 1


def test_an_empty_bundle_has_no_routes():
    assert extract("") == []


def test_a_route_in_a_template_literal_is_found():
    """A single-page application writes its routes as templates."""
    bundle = (
        'search(t){return this.http.get('
        '`${this.hostServer}/rest/products/search?q=${t}`)}'
    )

    routes = extract(bundle)

    assert ("/rest/products/search", ("q",)) in [(r.path, r.parameters) for r in routes]


def test_a_route_whose_value_is_only_known_at_run_time_is_dropped():
    """The value cannot be tested, so it is not offered."""
    bundle = 'post(`/${this.host}/${a}`, body);'

    assert extract(bundle) == []


def test_a_protocol_relative_path_is_dropped():
    """It names another host, not a route of this one."""
    bundle = 'fetch("//ipinfo.io/json");'

    assert extract(bundle) == []
