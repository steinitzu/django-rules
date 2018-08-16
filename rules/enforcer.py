from functools import wraps
import inspect

from rules.exceptions import PermissionDenied


class Enforcer:

    def __init__(self, user_loader=None, error_handler=None):
        if user_loader:
            self.user_loader(user_loader)
        if error_handler:
            self.error_handler(error_handler)

    def error_handler(self, fn):
        """
        Register an error handler that is called
        when permission is denied.
        The default error handler raises a 
        ``rules.exceptions.PermissionDenied``.

        Usable as method:

            enforcer.error_handler(lambda: raise CustomException())

        or as decorator:

            @enforcer.error_handler
            def handle_error():
                raise CustomException()

        :param fn: callable to handle permission denied errors
            The function will be passed the following arguments
            if possible:
            `predicate` The predicate that failed
            `user` The user object that was denied access
            `target` The target object user was denied access to
        """
        self._error_handler = fn
        return fn

    def user_loader(self, fn):
        """
        Register a user loader callback
        the current user when not explicitly provided
        to permission checking methods.

        The callback can return any type of object

        Usable as method

            enforcer.user_loader(lambda: current_user)

        Or as decorator

            @enforcer.user_loader
            def get_current_user():
                return current_user

        :param fn: Callbable to load current user

        """
        self._user_loader = fn
        return fn

    def requires(self, predicate, target_loader=None, on_failure=None):
        """
        Same behavior as `ensure`
        but can be used to decorate a function:

            @enforcer.requires(read_secret, target_loader=get_secret)
            def view_secret(secret_id):
                return get_secret(secret_id)

        :param predicate: ``Predicate` object to test
        :target_loader: `callable`, optional function
            to load the permission target for object level
            permissions
        :on_failure: `callable`, optional callback to handle errors
            Overrides the registered `error_handler`
        """
        def decorator(func):
            @wraps(func)
            def wrapper(*args, **kwargs):
                user = self._user_loader()
                target = target_loader() if target_loader else None
                self.ensure(predicate, user=user, target=target)
                return func(*args, **kwargs)
            return wrapper
        return decorator

    def ensure(self, predicate, user=None, target=None, on_failure=None):
        """
        Ensure that user has specified predicate.
        If predicate fails the `error_handler` is called.

        :param predicate: `Predicate`. The permission checking
           predicate to check against
        :param user: object, optional user object to check
           permission for, defaults to the registered `user_loader`
        :param target: object, optional target object
           for object level permission
        :on_failure: `callable`, optional callback to handle errors
            Overrides the registered `error_handler`
        """
        user = user or self._user_loader()
        if not predicate.test(user, target):
            self._fail(predicate, user, target, fail_handler=on_failure)

    def test(self, predicate, user=None, target=None):
        user = user or self._user_loader()
        return predicate.test(user, target)

    def _fail(self, predicate, user, target, fail_handler=None):
        fail_handler = fail_handler or self._error_handler
        fargs = predicate, user, target
        fail_handler(
            *fargs[:len(inspect.signature(fail_handler).parameters)]
        )

    def _default_error_handler(self, predicate, user=None, target=None):
        raise PermissionDenied(
            'Access denied for user "{}"'.format(user),
            predicate, user
        )

    def _default_user_loader(self):
        raise NotImplementedError(
            """
            User loader not registered.
            Use @enforcer.user_loader to register.
            """
        )

    _user_loader = _default_user_loader
    _error_handler = _default_error_handler
