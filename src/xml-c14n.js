// From https://github.com/Samsung/webIDE-common-tizentv/blob/dev/lib/exclusive-canonicalization.js, with modifications to include some other functions required.

class ExclusiveCanonicalization {
    constructor() {
        this.includeComments = false;
    }

    attrCompare(a, b) {
        if (!a.namespaceURI && b.namespaceURI) { return -1; }
        if (!b.namespaceURI && a.namespaceURI) { return 1; }

        let left = a.namespaceURI + a.localName
        let right = b.namespaceURI + b.localName

        if (left === right) return 0
        else if (left < right) return -1
        else return 1

    };

    nsCompare(a, b) {
        let attr1 = a.prefix;
        let attr2 = b.prefix;
        if (attr1 == attr2) { return 0; }
        return attr1.localeCompare(attr2);
    };

    renderAttrs(node, defaultNS) {
        let a, i, attr
            , res = []
            , attrListToRender = [];



        if (node.attributes) {
            for (i = 0; i < node.attributes.length; ++i) {
                attr = node.attributes[i];
                //ignore namespace definition attributes
                if (attr.name.indexOf("xmlns") === 0) { continue; }
                attrListToRender.push(attr);
            }
        }

        attrListToRender.sort(this.attrCompare);

        for (a in attrListToRender) {
            if (!attrListToRender.hasOwnProperty(a)) { continue; }

            attr = attrListToRender[a];
            res.push(" ", attr.name, '="', encodeSpecialCharactersInAttribute(attr.value), '"');
        }

        return res.join("");
    };


    /**
     * Create the string of all namespace declarations that should appear on this element
     *
     * @param {Node} node. The node we now render
     * @param {Array} prefixesInScope. The prefixes defined on this node
     *                parents which are a part of the output set
     * @param {String} defaultNs. The current default namespace
     * @return {String}
     * @api private
     */
    renderNs(node, prefixesInScope, defaultNs, defaultNsForPrefix, inclusiveNamespacesPrefixList) {
        let a, i, p, attr
            , res = []
            , newDefaultNs = defaultNs
            , nsListToRender = []
            , currNs = node.namespaceURI || "";

        //handle the namespaceof the node itself
        if (node.prefix) {
            if (prefixesInScope.indexOf(node.prefix) == -1) {
                nsListToRender.push({ "prefix": node.prefix, "namespaceURI": node.namespaceURI || defaultNsForPrefix[node.prefix] });
                prefixesInScope.push(node.prefix);
            }
        }
        else if (defaultNs != currNs) {
            //new default ns
            newDefaultNs = node.namespaceURI;
            res.push(' xmlns="', newDefaultNs, '"');
        }

        //handle the attributes namespace
        if (node.attributes) {
            for (i = 0; i < node.attributes.length; ++i) {
                attr = node.attributes[i];

                //handle all prefixed attributes that are included in the prefix list and where
                //the prefix is not defined already
                if (attr.prefix && prefixesInScope.indexOf(attr.localName) === -1 && inclusiveNamespacesPrefixList.indexOf(attr.localName) >= 0) {
                    nsListToRender.push({ "prefix": attr.localName, "namespaceURI": attr.value });
                    prefixesInScope.push(attr.localName);
                }

                //handle all prefixed attributes that are not xmlns definitions and where
                //the prefix is not defined already
                if (attr.prefix && prefixesInScope.indexOf(attr.prefix) == -1 && attr.prefix != "xmlns" && attr.prefix != "xml") {
                    nsListToRender.push({ "prefix": attr.prefix, "namespaceURI": attr.namespaceURI });
                    prefixesInScope.push(attr.prefix);
                }
            }
        }

        nsListToRender.sort(this.nsCompare);

        //render namespaces
        for (a in nsListToRender) {
            if (!nsListToRender.hasOwnProperty(a)) { continue; }

            p = nsListToRender[a];
            res.push(" xmlns:", p.prefix, '="', p.namespaceURI, '"');
        }

        return { "rendered": res.join(""), "newDefaultNs": newDefaultNs };
    };

    processInner(node, prefixesInScope, defaultNs, defaultNsForPrefix, inclusiveNamespacesPrefixList) {
        if (node.data) { return encodeSpecialCharactersInText(node.data); }

        let i, pfxCopy
            , ns = this.renderNs(node, prefixesInScope, defaultNs, defaultNsForPrefix, inclusiveNamespacesPrefixList)
            , res = ["<", node.tagName, ns.rendered, this.renderAttrs(node, ns.newDefaultNs), ">"];


        for (i = 0; i < node.childNodes.length; ++i) {
            pfxCopy = prefixesInScope.slice(0);
            res.push(this.processInner(node.childNodes[i], pfxCopy, ns.newDefaultNs, defaultNsForPrefix, inclusiveNamespacesPrefixList));
        }


        res.push("</", node.tagName, ">");
        return res.join("");
    };


    /**
     * Perform canonicalization of the given node
     *
     * @param {Node} node
     * @return {String}
     * @api public
     */
    process(node, options) {
        options = options || {};
        let inclusiveNamespacesPrefixList = options.inclusiveNamespacesPrefixList || [];
        let defaultNs = options.defaultNs || "";
        let defaultNsForPrefix = options.defaultNsForPrefix || {};
        if (!(inclusiveNamespacesPrefixList instanceof Array)) { inclusiveNamespacesPrefixList = inclusiveNamespacesPrefixList.split(' '); }

        let res = this.processInner(node, [], defaultNs, defaultNsForPrefix, inclusiveNamespacesPrefixList);
        return res;
    };

    getAlgorithmName() {
        return "http://www.w3.org/2001/10/xml-exc-c14n#";
    };
}

const xmlSpecialToEncodedAttribute = {
    '&': '&amp;',
    '<': '&lt;',
    '"': '&quot;',
    '\r': '&#xD;',
    '\n': '&#xA;',
    '\t': '&#x9;'
}

const xmlSpecialToEncodedText = {
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '\r': '&#xD;'
}

function encodeSpecialCharactersInAttribute(attributeValue) {
    return attributeValue
        .replace(/[\r\n\t ]+/g, ' ') // White space normalization (Note: this should normally be done by the xml parser) See: https://www.w3.org/TR/xml/#AVNormalize
        .replace(/([&<"\r\n\t])/g, function (str, item) {
            // Special character normalization. See:
            // - https://www.w3.org/TR/xml-c14n#ProcessingModel (Attribute Nodes)
            // - https://www.w3.org/TR/xml-c14n#Example-Chars
            return xmlSpecialToEncodedAttribute[item]
        });
}

function encodeSpecialCharactersInText(text) {
    return text
        .replace(/\r\n?/g, '\n')  // Line ending normalization (Note: this should normally be done by the xml parser). See: https://www.w3.org/TR/xml/#sec-line-ends
        .replace(/([&<>\r])/g, function (str, item) {
            // Special character normalization. See:
            // - https://www.w3.org/TR/xml-c14n#ProcessingModel (Text Nodes)
            // - https://www.w3.org/TR/xml-c14n#Example-Chars
            return xmlSpecialToEncodedText[item]
        });
}


module.exports = ExclusiveCanonicalization;

