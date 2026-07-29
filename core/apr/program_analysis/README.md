# Compatibility namespace

The canonical providers now live in `core/program_analysis`.  The Python
modules in this directory are import-compatible aliases so existing callers
keep the same provider functions and process-wide caches.
