from werkzeug.exceptions import Forbidden

from rules.enforcer import Enforcer


class FlaskEnforcer(Enforcer):

    def _default_error_handler(self, predicate, user=None, target=None):
        raise Forbidden()
