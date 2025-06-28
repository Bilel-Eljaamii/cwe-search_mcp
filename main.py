# -*- coding: utf-8 -*-
#!/usr/bin/python

"""
CWE Search Service Implementation

This module provides a Python interface to MITRE's Common Weakness Enumeration (CWE)
database through the official CWE API. It implements a search service that allows querying
vulnerability information using MCP server framework.

Key Functionalities:
- CWE content version retrieval
- Vulnerability lookup by CWE ID
- Keyword search across weakness descriptions
- Category and view management
- Vulnerability relationship queries:
  - Parents/children
  - Ancestors/descendants
  - Relationships

The service implements the following MITRE CWE API endpoints:
  /cwe/version
  /cwe/{id}
  /weakness/{id(s)}
  /cwe/category/{id(s)}
  /cwe/view/{id(s)}
  /cwe/{id}/parents
  /cwe/{id}/children
  /cwe/{id}/ancestors
  /cwe/{id}/descendants

Usage:
  Run as main module: `python main.py`
  Integrate with MCP-compatible systems via stdio transport

Dependencies:
  - requests (for API communication)
  - FastMCP framework

Authentication:
  The MITRE CWE API is public and requires no authentication.

Note:
  All CWE IDs can be provided with or without the 'CWE-' prefix.
  The service automatically normalizes input formats.

MITRE CWE API Documentation:
  https://cwe.mitre.org/data/downloads.html
"""

from typing import Optional, Dict, Any
import logging
import requests
from mcp.server.fastmcp import FastMCP

#class cwe-search_mcp
CWE_API_VERSION = "v1"
BASE_URL = f"https://cwe-api.mitre.org/api/{CWE_API_VERSION}/cwe/"

# Create an MCP server
# Common Weakness Enumeration (CWE) Search Service
mcp = FastMCP("cwe-search_mcp")

logger = logging.getLogger(__name__)
logger.info("Starting cwe-search_mcp")


def get_requests(endpoint: str, params: Optional[Dict] = None, t_out=15) -> Dict[str, Any]:
    """Make GET requests to CWE API with error handling"""
    session = requests.Session()
    url = f"{BASE_URL}{endpoint}"
    try:
        response = session.get(url, params=params, timeout=t_out)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        error_msg = f"API request to {url} failed: {str(e)}"
        logger.error(error_msg)
        return {
            "error": error_msg,
            "status_code": getattr(e.response, 'status_code', None)
        }

@mcp.tool()
def get_cwe_content_version() -> Dict[str, Any]:
    """
    Get CWE content version information
    Calls endpoint: GET /version
    """
    return get_requests("version")

@mcp.tool()
def get_cwe_info(ids: str) -> Dict[str, Any]:
    """
    Get metadata for specified CWE ID(s)

    Args:
        ids: Comma-separated list of CWE IDs (with or without 'CWE-' prefix)
             Example: "79" or "CWE-79" or "79,89,CWE-22"

    Returns:
        Dictionary with CWE metadata or error information
    """
    # Normalize and validate input
    id_list = []
    for id_str in ids.split(','):
        clean_id = id_str.strip().upper().replace('CWE-', '')
        if clean_id.isdigit():
            id_list.append(clean_id)
        else:
            return {
                "error": f"Invalid CWE ID format: {id_str}",
                "status_code": 400
            }

    if not id_list:
        return {
            "error": "No valid CWE IDs provided",
            "status_code": 400
        }

    # Fetch data for all valid IDs
    results = {}
    for cwe_id in id_list:
        response = get_requests(f"{cwe_id}")
        if "error" in response:
            # Enhance error information
            response["cwe_id"] = cwe_id
            results[cwe_id] = response
        else:
            results[cwe_id] = response

    return results

@mcp.tool()
def get_cwe_weakness(ids: str) -> Dict[str, Any]:
    """
    Get CWE weaknesses by ID(s) or all weaknesses

    Args:
        ids: Comma-separated CWE IDs or "all" to retrieve all weaknesses
             Examples: "79", "CWE-89,125", "all"

    Returns:
        Dictionary with "Weaknesses" array or error information
    """
    # Handle "all" case
    if ids.strip().lower() == "all":
        return get_requests("weakness/all", t_out=60)

    # Process individual IDs
    id_list = []
    for id_str in ids.split(','):
        clean_id = id_str.strip().upper().replace('CWE-', '')
        if clean_id.isdigit():
            id_list.append(clean_id)

    if not id_list:
        return {
            "error": "No valid CWE IDs provided",
            "status_code": 400
        }

    # Fetch weaknesses
    weaknesses = []
    errors = []

    for cwe_id in id_list:
        response = get_requests(f"weakness/{cwe_id}")
        if "error" in response:
            errors.append({
                "cwe_id": cwe_id,
                "error": response["error"],
                "status_code": response.get("status_code", 500)
            })
        elif "Weaknesses" in response:
            weaknesses.extend(response["Weaknesses"])
        else:
            errors.append({
                "cwe_id": cwe_id,
                "error": "Unexpected API response format",
                "status_code": 500
            })

    # Return results or errors
    if weaknesses:
        if errors:
            # Partial success
            return {
                "Weaknesses": weaknesses,
                "errors": errors
            }
        return {"Weaknesses": weaknesses}
    return {
        "errors": errors,
        "status_code": 404 if any(e.get("status_code") == 404 for e in errors) else 500
    }

@mcp.tool()
def get_cwe_category(ids: str) -> Dict[str, Any]:
    """
    Get CWE categories by ID(s) or all categories

    Args:
        ids: Comma-separated category IDs (with/without 'CWE-') or "all"
             Examples: "123", "CWE-456,789", "all"

    Returns:
        Dictionary with "Categories" array or error information
    """
    # Handle "all" case
    if ids.strip().lower() == "all":
        return get_requests("category/all")

    # Process individual IDs
    id_list = []
    for id_str in ids.split(','):
        clean_id = id_str.strip().upper().replace('CWE-', '')
        if clean_id:
            id_list.append(clean_id)

    if not id_list:
        return {
            "error": "No valid category IDs provided",
            "status_code": 400
        }

    # Fetch categories
    categories = []
    errors = []

    for cat_id in id_list:
        response = get_requests(f"category/{cat_id}")
        if "error" in response:
            errors.append({
                "category_id": cat_id,
                "error": response["error"],
                "status_code": response.get("status_code", 500)
            })
        elif "Categories" in response:
            categories.extend(response["Categories"])
        else:
            errors.append({
                "category_id": cat_id,
                "error": "Unexpected API response format",
                "status_code": 500
            })

    # Return results or errors
    if categories:
        if errors:
            # Partial success
            return {
                "Categories": categories,
                "errors": errors
            }
        return {"Categories": categories}
    return {
        "errors": errors,
        "status_code": 404 if any(e.get("status_code") == 404 for e in errors) else 500
    }

@mcp.tool()
def get_cwe_view(ids: str) -> Dict[str, Any]:
    """
    Get CWE views by ID(s) or all views

    Args:
        ids: Comma-separated view IDs (with/without 'CWE-') or "all"
             Examples: "1000", "CWE-1010,1020", "all"

    Returns:
        Dictionary with "Views" array or error information
    """
    # Handle "all" case
    if ids.strip().lower() == "all":
        return get_requests("view/all")

    # Process individual IDs
    id_list = []
    for id_str in ids.split(','):
        clean_id = id_str.strip().upper().replace('CWE-', '')
        if clean_id:
            id_list.append(clean_id)

    if not id_list:
        return {
            "error": "No valid view IDs provided",
            "status_code": 400
        }

    # Fetch views
    views = []
    errors = []

    for view_id in id_list:
        response = get_requests(f"view/{view_id}")
        if "error" in response:
            errors.append({
                "view_id": view_id,
                "error": response["error"],
                "status_code": response.get("status_code", 500)
            })
        elif "Views" in response:
            views.extend(response["Views"])
        else:
            errors.append({
                "view_id": view_id,
                "error": "Unexpected API response format",
                "status_code": 500
            })

    # Return results or errors
    if views:
        if errors:
            # Partial success
            return {
                "Views": views,
                "errors": errors
            }
        return {"Views": views}
    return {
        "errors": errors,
        "status_code": 404 if any(e.get("status_code") == 404 for e in errors) else 500
    }

@mcp.tool()
def get_cwe_parents(cwe_id: str, view: Optional[str] = None) -> Dict[str, Any]:
    """
    Get parents of a specified CWE weakness, filtered by view

    Args:
        cwe_id: CWE ID (with/without 'CWE-')
        view: Optional view identifier to filter relationships

    Returns:
        Dictionary with "Parents" array or error information
    """
    # Normalize CWE ID
    clean_id = cwe_id.strip().upper().replace('CWE-', '')
    if not clean_id.isdigit():
        return {
            "error": f"Invalid CWE ID format: {cwe_id}",
            "status_code": 400
        }

    # Prepare parameters
    params = {}
    if view:
        params["view"] = view

    # Make API request
    response = get_requests(f"{clean_id}/parents", params=params)

    # Handle error responses
    if "error" in response:
        return {
            "error": response["error"],
            "status_code": response.get("status_code", 500),
            "cwe_id": clean_id
        }

    # Handle successful response
    if isinstance(response, list):
        return {"Parents": response}
    return {
        "error": "Unexpected API response format",
        "status_code": 500,
        "cwe_id": clean_id,
        "details": f"Expected array but got {type(response).__name__}"
    }

@mcp.tool()
def get_cwe_descendants(cwe_id: str, view: Optional[str] = None) -> Dict[str, Any]:
    """
    Get descendants of a specified CWE weakness, filtered by view

    Args:
        cwe_id: CWE ID (with/without 'CWE-')
        view: Optional view identifier to filter relationships

    Returns:
        Dictionary with "Descendants" array or error information
    """
    # Normalize CWE ID
    clean_id = cwe_id.strip().upper().replace('CWE-', '')
    if not clean_id.isdigit():
        return {
            "error": f"Invalid CWE ID format: {cwe_id}",
            "status_code": 400,
            "cwe_id": cwe_id
        }

    # Prepare parameters
    params = {}
    if view:
        params["view"] = view

    # Make API request
    response = get_requests(f"{clean_id}/descendants", params=params)

    # Handle error responses
    if "error" in response:
        return {
            "error": response["error"],
            "status_code": response.get("status_code", 500),
            "cwe_id": clean_id
        }

    # Handle successful response
    if "Descendants" in response:
        return response
    return {
        "error": "Unexpected API response format - missing 'Descendants' key",
        "status_code": 500,
        "cwe_id": clean_id,
        "api_response": response
    }

@mcp.tool()
def get_cwe_children(cwe_id: str, view: Optional[str] = None) -> Dict[str, Any]:
    """
    Get children of a specified CWE weakness, filtered by view

    Args:
        cwe_id: CWE ID (with/without 'CWE-')
        view: Optional view identifier to filter relationships

    Returns:
        Dictionary with "Children" array or error information
    """
    # Normalize CWE ID
    clean_id = cwe_id.strip().upper().replace('CWE-', '')
    if not clean_id.isdigit():
        return {
            "error": f"Invalid CWE ID format: {cwe_id}",
            "status_code": 400,
            "cwe_id": cwe_id
        }

    # Prepare parameters
    params = {}
    if view:
        params["view"] = view

    # Make API request
    response = get_requests(f"{clean_id}/children", params=params)

    # Handle error responses
    if "error" in response:
        return {
            "error": response["error"],
            "status_code": response.get("status_code", 500),
            "cwe_id": clean_id
        }

    # Handle successful response
    if isinstance(response, list):
        return {"Children": response}
    return {
        "error": "Unexpected API response format - expected array",
        "status_code": 500,
        "cwe_id": clean_id,
        "api_response": response
    }

@mcp.tool()
def get_cwe_ancestors(cwe_id: str,
                      view: Optional[str] = None,
                      primary: Optional[bool] = None) -> Dict[str, Any]:
    """
    Get ancestors of a specified CWE weakness, filtered by view and primary flag

    Args:
        cwe_id: CWE ID (with/without 'CWE-')
        view: Optional view identifier to filter relationships
        primary: Limit ancestors to include only primary parents

    Returns:
        Dictionary with "Ancestors" array or error information
    """
    # Normalize CWE ID
    clean_id = cwe_id.strip().upper().replace('CWE-', '')
    if not clean_id.isdigit():
        return {
            "error": f"Invalid CWE ID format: {cwe_id}",
            "status_code": 400,
            "cwe_id": cwe_id
        }

    # Prepare parameters
    params = {}
    if view:
        params["view"] = view
    if primary is not None:
        params["primary"] = str(primary).lower()

    # Make API request
    response = get_requests(f"{clean_id}/ancestors", params=params)

    # Handle error responses
    if "error" in response:
        return {
            "error": response["error"],
            "status_code": response.get("status_code", 500),
            "cwe_id": clean_id
        }

    # Handle successful response
    if "Ancestors" in response:
        return response
    return {
        "error": "Unexpected API response format - missing 'Ancestors' key",
        "status_code": 500,
        "cwe_id": clean_id,
        "api_response": response
        }

def main():
    """
    Entry point for the CWE Search Service.

    Starts the MCP server using standard I/O transport.
    This allows the service to communicate via stdin/stdout, making it suitable
    for command-line use and integration with other systems through pipes.

    The service will:
    1. Initialize all registered tool functions
    2. Listen for incoming requests via standard input
    3. Process requests through the defined endpoints
    4. Return responses via standard output
    5. Continue running until terminated

    Usage:
    - Run as standalone script: `python main.py`
    - Integrate with other systems through stdio pipes
    """
    mcp.run(transport="streamable-http")

# Run the server
if __name__ == "__main__":
    mcp.run(transport='stdio')
