"""One-click Geneza console for a Horizon instances panel.

Adds a "Console" row action that opens a live shell on the selected VM. The
launch is authorized by the SIGNED-IN TENANT'S OWN Keystone token, which Horizon
already holds — Horizon never carries a Geneza credential of its own, so there
is no API key to distribute or leak, and this panel can only ever act for the
user currently driving it.

See deploy/openstack/horizon-geneza-console/README.md for wiring, and
docs/hosted-ui-launch-spec.md for the security model.
"""

import logging

import requests
from django.conf import settings
from django.http import HttpResponseRedirect
from django.utils.translation import gettext_lazy as _
from django.views import generic
from horizon import exceptions
from horizon import tables

LOG = logging.getLogger(__name__)

LAUNCH_TIMEOUT_SECONDS = 10


class GenezaConsoleAction(tables.LinkAction):
    """Row action: Project -> Compute -> Instances -> Console."""

    name = "geneza_console"
    verbose_name = _("Console")
    url = "horizon:project:instances:geneza_console"
    classes = ("btn-console",)

    def allowed(self, request, instance=None):
        if not getattr(settings, "GENEZA_CONTROLLER_URL", ""):
            return False
        return instance is not None and instance.status == "ACTIVE"


class GenezaConsoleView(generic.View):
    """Mint a single-use launch URL and send the browser to it.

    The launch URL is a short-lived (~60s), single-use bearer credential. It is
    handed straight to the browser as a redirect and is never logged: the code
    itself rides the URL FRAGMENT, so it does not reach Horizon's access log,
    any proxy in front of it, or a Referer header.
    """

    def get(self, request, instance_id):
        base = settings.GENEZA_CONTROLLER_URL.rstrip("/")
        svc_uid = settings.GENEZA_SERVICE_UID
        # The token the tenant is signed in to Horizon with. It is project-scoped
        # and belongs to them — Geneza validates it against this cloud's Keystone
        # and derives the workspace, roles, and project from the validation body.
        token = request.user.token.id

        try:
            resp = requests.post(
                "%s/openstack/%s/launch" % (base, svc_uid),
                json={"instance_id": instance_id, "token": token, "action": "shell"},
                timeout=LAUNCH_TIMEOUT_SECONDS,
                verify=getattr(settings, "GENEZA_VERIFY_TLS", True),
            )
        except requests.RequestException as exc:
            LOG.warning("geneza launch request failed for %s: %s", instance_id, exc)
            exceptions.handle(request, _("Could not reach the Geneza controller."))
            return HttpResponseRedirect(_instances_index())

        if resp.status_code != 200:
            # The controller's message is the useful part: policy denial, an
            # instance that is not a Geneza node, an unbound project, and so on.
            reason = _error_reason(resp)
            LOG.info("geneza launch denied for %s: %s (%s)", instance_id, reason, resp.status_code)
            exceptions.handle(request, _("Console unavailable: %s") % reason)
            return HttpResponseRedirect(_instances_index())

        launch_url = resp.json().get("launch_url")
        if not launch_url:
            exceptions.handle(request, _("The controller returned no console URL."))
            return HttpResponseRedirect(_instances_index())
        return HttpResponseRedirect(launch_url)


def _error_reason(resp):
    try:
        return resp.json().get("error") or resp.reason
    except ValueError:
        return resp.reason


def _instances_index():
    from django.urls import reverse

    return reverse("horizon:project:instances:index")
