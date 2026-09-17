"""Display configuration for result categories.

Change a ``priority`` value to reorder categories in the web interface.
Lower values appear first.
"""

CATEGORIES = (
    {"key": "overview", "label": "Log Overview", "description": "Details extracted from the uploaded log.", "priority": 10},
    {"key": "critical", "label": "Critical Issues", "description": "Items most likely to prevent a successful run or cause major issues with a run", "priority": 20},
    {"key": "error", "label": "Errors", "description": "Errors that occur during a run that do not prevent the run finishing, but may cause undesired results.", "priority": 30},
    {"key": "warning", "label": "Warnings", "description": "Potential problems worth reviewing before your next run.", "priority": 40},
    {"key": "schema", "label": "Schema issues", "description": "Deprecated or invalid configuration syntax that should be updated.", "priority": 50},
    {"key": "advice", "label": "Advice", "description": "Configuration and performance improvements.", "priority": 60},
)


def category_configuration() -> list[dict]:
    """Return JSON-safe category configuration in priority order."""
    return sorted((dict(category) for category in CATEGORIES), key=lambda category: category["priority"])
