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
    size_t docSize;
    xmlDocPtr doc = NULL;
    
    if (size == 0 || size > 50000)
        return(0);

    xmlFuzzDataInit(data, size);
    
    xmlFuzzReadEntities();
    docBuffer = xmlFuzzMainEntity(&docSize);
    if (docBuffer == NULL) {
        xmlFuzzDataCleanup();
        return(0);  // Add early return with cleanup
    }

    // Add better error handling for all operations
    doc = xmlReadMemory(docBuffer, docSize, "catalog.xml", NULL, 0);
    if (doc == NULL) {
        xmlFuzzDataCleanup();
        return(0);  // Early return if document can't be parsed
    }

    /* Create a new catalog */
    catalog = xmlNewCatalog(1);
    if (catalog == NULL) {
        xmlFreeDoc(doc);
        xmlFuzzDataCleanup();
        xmlResetLastError();
        return(0);
    }

    /* Test catalog functionality */
    xmlCatalogAdd(BAD_CAST "catalog", NULL, doc->URL);
    
    /* Test various catalog types and functions */
    const char *uri = "http://example.com/test.dtd";
    const char *pubId = "-//Example//DTD Test//EN";
    
    /* System entries */
    xmlCatalogAdd(BAD_CAST "system", BAD_CAST uri, BAD_CAST "file:///test.dtd");
    xmlChar *resolved = xmlCatalogResolveSystem(BAD_CAST uri);
    xmlFree(resolved);
    
    /* Public entries */
    xmlCatalogAdd(BAD_CAST "public", BAD_CAST pubId, BAD_CAST "file:///pub.dtd");
    resolved = xmlCatalogResolvePublic(BAD_CAST pubId);
    xmlFree(resolved);
    
    /* Rewrite rules */
    xmlCatalogAdd(BAD_CAST "rewriteSystem", BAD_CAST "http://example.org", 
                BAD_CAST "file:///local/");
    resolved = xmlCatalogResolve(BAD_CAST "http://example.org/test.dtd", NULL);
    xmlFree(resolved);
    
    /* Test catalog defaults */
    xmlCatalogSetDefaultPrefer(XML_CATA_PREFER_PUBLIC);
    xmlCatalogSetDefaults(XML_CATA_ALLOW_GLOBAL);
    
    /* Clean up */
    if (doc != NULL)
        xmlFreeDoc(doc);
    if (catalog != NULL)
        xmlFreeCatalog(catalog);
    
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
