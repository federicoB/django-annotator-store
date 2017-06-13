.. _CHANGELOG:

CHANGELOG
=========

Release 0.5
-----------

Initial release of `annotator_store` as a stand-alone django application,
refactored out of the `Readux <https://github.com/emory-libraries/readux>`_
codebase.

* Support for custom Annotation model via **ANNOTATOR_ANNOTATION_MODEL**
  setting and `annotator_store.models.BaseAnnotation` abstract model
* Configurable support for normal Django permissions *or* per-item
  permissions via **django-guardian** (*NOTE* that per-item permissions
  functionality is not fully tested or supported and should be
  considered alpha quality)
* Annotation text and quote fields marked as optional for use in Django admin
* Supports both Python 3.x and Python 2.7
* Includes example templates with code for initializing an annotator.js
  instance and connecting it to annotator_store as a backend.