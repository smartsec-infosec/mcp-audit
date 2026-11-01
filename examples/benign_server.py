"""Benign demo server: well-constrained, annotated, read-only tools. Should produce no medium+ findings."""
import os, sys
sys.path.insert(0, os.path.dirname(__file__))
from _mini_mcp import serve

tools = [
    {"name": "get_time", "description": "Return the current time in a given IANA timezone.",
     "inputSchema": {"type": "object", "properties": {"tz": {"type": "string", "enum": ["UTC", "Europe/London"]}},
                     "additionalProperties": False},
     "annotations": {"readOnlyHint": True, "openWorldHint": False}},
    {"name": "add_numbers", "description": "Add two integers and return the sum.",
     "inputSchema": {"type": "object", "properties": {"a": {"type": "integer"}, "b": {"type": "integer"}},
                     "required": ["a", "b"], "additionalProperties": False},
     "annotations": {"readOnlyHint": True, "openWorldHint": False}},
]
serve("benign-demo", tools, prompts=[{"name": "summarise", "description": "Summarise a passage of text."}])
