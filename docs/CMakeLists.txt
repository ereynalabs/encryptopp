##
# @copyright Copyright (C) 2024, Ereyna Labs Ltd. - All Rights Reserved
# @file CMakeLists.txt
# @parblock
# This file is subject to the terms and conditions defined in file 'LICENSE.md',
# which is part of this source code package.  Proprietary and confidential.
# @endparblock
# @author Dave Linten <david@ereynalabs.com>
#

set(DOXYGEN_EXTRACT_ALL YES)
set(DOXYGEN_BUILTIN_STL_SUPPORT YES)


set(DOXYGEN_USE_MDFILE_AS_MAINPAGE "${CMAKE_SOURCE_DIR}/README.md")
set(DOXYGEN_PROJECT_LOGO "logo-small.png")
set(DOXYGEN_GENERATE_TREEVIEW YES)
set(DOXYGEN_HIDE_UNDOC_RELATIONS NO)
set(DOXYGEN_HAVE_DOT YES)
set(DOXYGEN_DOT_NUM_THREADS 1)
set(DOXYGEN_UML_LOOK YES)
set(DOXYGEN_UML_LIMIT_NUM_FIELDS 50)
set(DOXYGEN_TEMPLATE_RELATIONS YES)
set(DOXYGEN_DOT_IMAGE_FORMAT svg)
set(DOXYGEN_INTERACTIVE_SVG YES)
set(DOXYGEN_DOT_GRAPH_MAX_NODES 100)
set(DOXYGEN_DOT_TRANSPARENT YES)
set(DOXYGEN_FULL_PATH_NAMES NO)
set(DOXYGEN_HTML_HEADER headerFile)
set(DOXYGEN_HTML_EXTRA_FILES favicon.ico)

doxygen_add_docs(${APP_DOC_TARGET}
        "${CMAKE_SOURCE_DIR}/controllers"
        "${CMAKE_SOURCE_DIR}/helpers"
        "${CMAKE_SOURCE_DIR}/include"
        "${CMAKE_SOURCE_DIR}/models"
        "${CMAKE_SOURCE_DIR}/README.md"
        "${CMAKE_SOURCE_DIR}/favicon.ico")
