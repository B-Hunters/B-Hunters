# The Karton dashboard, extended with a worker-output page.
#
# The upstream image shows the task router: which services are connected,
# what they bind to, which tasks are pending or crashed.  It cannot show
# what a scanner *found*, because Karton forgets a task once it finishes
# and the result lives in the document the worker wrote.
#
# This image adds one page - /workers - that reads the documents the
# workers write into (the legacy reports document, the links collection
# and the js collection) and shows, per worker and per target, what came
# out.  It is the page that answers "did that scanner actually run, and
# what did it find".
FROM certpl/karton-dashboard:v1.6.0

COPY workers.py /tmp/patch/workers.py
COPY templates/workers.html /tmp/patch/workers.html

# The upstream image carries no MongoDB driver: the task router does not
# need one, only the B-Hunters workers do.  The worker-output page reads
# the documents the workers write into, so it needs the driver.
RUN pip install --no-cache-dir "pymongo>=4.6,<5"

# The image carries three copies of the package: the installed one in
# site-packages (which is the one the "karton-dashboard" console script
# imports), the source tree and the build tree.  All of them have to be
# patched, because which one wins depends on how the process is started.
RUN python3 - <<'PY'
import shutil
from pathlib import Path

source = Path("/tmp/patch")
for app in Path("/").glob("**/karton/dashboard/app.py"):
    package = app.parent
    if "site-packages" not in str(package) and "/app/service" not in str(package):
        continue

    shutil.copy(source / "workers.py", package / "workers.py")

    templates = package / "templates"
    templates.mkdir(exist_ok=True)
    shutil.copy(source / "workers.html", templates / "workers.html")

    text = app.read_text()
    if "workers_blueprint" not in text:
        app.write_text(
            text
            + "\n\nfrom .workers import workers_blueprint\n\n"
            + "app.register_blueprint(workers_blueprint)\n"
        )

    layout = templates / "layout.html"
    if layout.exists():
        markup = layout.read_text()
        if "workers.workers" not in markup:
            link = (
                '                    <li class="nav-item">\n'
                '                        <a class="nav-link" href="{{ url_for(\'workers.workers\') }}">workers</a>\n'
                "                    </li>\n"
            )
            markup = markup.replace("                </ul>", link + "                </ul>", 1)
            layout.write_text(markup)

    print(f"patched {package}")
PY

EXPOSE 5000
CMD ["karton-dashboard", "run", "--host", "0.0.0.0", "--port", "80"]
