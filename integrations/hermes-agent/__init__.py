"""Load the bundled Little Canary adapter as a Hermes directory plugin."""

# Pytest also imports a repository-root __init__.py as a top-level module.
# Hermes gives this file a namespaced package name; keep both import paths valid.
if __package__:
    from .little_canary.hermes_agent_plugin import register
else:
    from little_canary.hermes_agent_plugin import register

__all__ = ["register"]
