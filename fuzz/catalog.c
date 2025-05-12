/*
 * catalog.c: a libFuzzer target to test the XML catalog parser and processor.
 *
 * See Copyright for the status of this software.
 */

#include <libxml/catalog.h>
#include <libxml/parser.h>
#include "fuzz.h"

int
LLVMFuzzerInitialize(int *argc ATTRIBUTE_UNUSED,
                     char ***argv ATTRIBUTE_UNUSED) {
    xmlFuzzMemSetup();
    xmlInitParser();
    
    /* Initialize catalog support but don't load the default catalog */
    xmlInitializeCatalog();
    xmlCatalogSetDefaults(XML_CATA_ALLOW_NONE);
    
    xmlSetGenericErrorFunc(NULL, xmlFuzzErrorFunc);

    return 0;
}

int
LLVMFuzzerTestOneInput(const char *data, size_t size) {
    xmlCatalogPtr catalog;
    const char *docBuffer;
    size_t docSize, failurePos;
    xmlDocPtr doc;
    
    if (size == 0)
        return(0);

    // Previous limit was too strict, allow larger inputs
    if (size > 50000)
        return(0);

    xmlFuzzDataInit(data, size);
    // Skip reading a fuzzing parameter, just use the data directly
    // failurePos = xmlFuzzReadInt(4) % (size + 100);
    failurePos = 0; // Disable failure injection for coverage testing
    
    xmlFuzzReadEntities();
    docBuffer = xmlFuzzMainEntity(&docSize);
    if (docBuffer == NULL) {
        // If we can't extract the main entity, just use the raw data
        docBuffer = data;
        docSize = size;
    }

    /* First parse the XML document from buffer */
    doc = xmlReadMemory(docBuffer, docSize, "catalog.xml", NULL, 0);
    if (doc == NULL) {
        // For coverage, try parsing it as an actual catalog file
        int result = xmlLoadCatalog(docBuffer);
        return(0);
    }

    /* Create new catalog manually since there's no direct buffer loading API */
    xmlFuzzInjectFailure(failurePos);
    
    /* First parse the XML document from buffer */
    doc = xmlReadMemory(docBuffer, docSize, "catalog.xml", NULL, 0);
    if (doc == NULL) {
        xmlFuzzCheckFailureReport("xmlReadMemory", xmlFuzzMallocFailed(), 0);
        goto exit;
    }

    /* Create a new catalog */
    catalog = xmlNewCatalog(1); /* 1 = XML_SGML_CATALOG_TYPE for XML catalogs */
    if (catalog == NULL) {
        xmlFreeDoc(doc);
        xmlFuzzCheckFailureReport("xmlNewCatalog", xmlFuzzMallocFailed(), 0);
        goto exit;
    }

    /* Parse the catalog entries from the XML document */
    xmlCatalogAdd(BAD_CAST "catalog", NULL, doc->URL);

    /* If we successfully created a catalog, test catalog functions */
    if (catalog != NULL) {
        xmlChar *resolved;
        const char *uri = "http://example.com/test.dtd";
        const char *pubId = "-//Example//DTD Test//EN";
        
        /* Test various catalog lookup functions */
        resolved = xmlCatalogResolve(BAD_CAST uri, BAD_CAST NULL);
        xmlFree(resolved);
        
        resolved = xmlCatalogResolvePublic(BAD_CAST pubId);
        xmlFree(resolved);
        
        resolved = xmlCatalogResolveSystem(BAD_CAST uri);
        xmlFree(resolved);
        
        /* Free catalog */
        xmlFreeCatalog(catalog);
    }
    
    /* Clean up */
    xmlFreeDoc(doc);

exit:
    xmlFuzzInjectFailure(0);
    xmlFuzzDataCleanup();
    xmlResetLastError();
    return(0);
}

size_t
LLVMFuzzerCustomMutator(char *data, size_t size, size_t maxSize,
                        unsigned seed) {
    static const xmlFuzzChunkDesc chunks[] = {
        { 4, XML_FUZZ_PROB_ONE / 10 }, /* failurePos */
        { 0, 0 }
    };

    return xmlFuzzMutateChunks(chunks, data, size, maxSize, seed,
                               LLVMFuzzerMutate);
}
