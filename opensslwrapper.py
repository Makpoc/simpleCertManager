import certchain

__author__ = 'makpoc'

import os
from certchain import ChainNode
from certchain import CertWithFile
from OpenSSL import *

serial = 0
cert_password = "SECRET123"


def loadcertificate(f):
    return crypto.load_pkcs12(open(f, 'rb').read(), cert_password)


def loadcertificates(fromfolder):
    certs = {}
    for f in os.listdir(fromfolder):
        try:
            certs[f] = loadcertificate(os.path.join(fromfolder, f))
        except:
            print "[*] Failed to load file %s" % f
    return certs


def _is_selfsigned(cert):
    return cert.get_certificate().get_issuer() == cert.get_certificate().get_subject()


def construct_chains(certs):
    if not certs:
        return None
    allnodes = []
    rootnode = ChainNode(None)
    for item in certs.items():
        allnodes.append(ChainNode(CertWithFile(item[1], item[0])))

    for node in allnodes:
        if _is_selfsigned(node.get().get_cert()):
            rootnode.add_child(node)
            continue
        for node2 in allnodes:
            if node == node2:
                continue
            if _is_issued_by(node.get().get_cert(), node2.get().get_cert()):
                node2.add_child(node)
    return rootnode.get_children()


def _is_issued_by(cert1, cert2):
    """
    Takes two dictionaries in the form {subject: "subject", issuer: "issuer"}.
    Returns True if cert1 is signed by cert2, False otherwise
    """
    cert1_issuer = construct_subject_from_component(cert1.get_certificate().get_issuer().get_components())
    cert2_subject = construct_subject_from_component(cert2.get_certificate().get_subject().get_components())
    return cert1_issuer == cert2_subject

#def construct_chain(pkcs12certs):
#    """
#        Accepts a dictionary with files and certificate objects in the form:
#        {file: OpenSSL.crypto.PKCS12}
#        Constructs and returns a list in the following form:
#        [[(file1,cert1), (file2,cert2), (file3,cert3)], [(file21, cert21), (file21, cert21)]]
#        where cert3 is signed by cert2, cert2 is signed by cert1, etc
#    """
#   remaining = pkcs12certs
#   result = []
#   while True:
#    chain, remaining = _extract_single_chain(remaining)
#    if chain:
#        result.append(chain)
#    if not remaining:
#        return result


#def _extract_single_chain(pkcs12certs):
#    chain = []
#    remaining = {}
#    current_f, p12 = pkcs12certs.popitem()
#    chain.append((current_f, p12))
#    for (f, cert) in pkcs12certs.items():
#        c = _get_issuer(p12, cert)
#        if c:
#            if cert == c[0]:
#                chain.insert(0, (f, cert))
#            else:
#                chain.append((f, cert))
#        else:
#            remaining[f] = cert
#
#    return chain, remaining


def _generateKeyPair(algorithm=crypto.TYPE_RSA, size=4096):
    """
    Create a public/private key pair.

    algorithm - crypto.TYPE_RSA or crypto.TYPE_DSA
    size - Number of bits to use in the key
    Returns: The public/private key pair in a PKey object
    """
    keyPair = crypto.PKey()
    keyPair.generate_key(algorithm, size)
    return keyPair


def _generateCertRequest(pkey, digest="md5", **kwargs):
    """
    Creates a certificate request.

    pkey - The key to associate with the request
    digest - Digestion method to use for signing, default is md5
    **kwargs - The subject of the request, possible arguments are:
    C - Country name
    ST - State or province name
    L - Locality name
    O - Organization name
    OU - Organizational unit name
    CN - Common name
    emailAddress - E-mail address
    Returns: The certificate request in an X509Req object
    """
    req = crypto.X509Req()
    subj = req.get_subject()

    if not "CN" in kwargs.keys():
        kwargs["CN"] = "GeneratedCAName"

    for (key, value) in kwargs.items():
        setattr(subj, key, value)

    req.set_pubkey(pkey)
    req.sign(pkey, digest)
    return req


def _signCertificateRequest(signingReq, issuerSubject, issuerKey, (notBefore, notAfter), extensions=None,
                            digest="md5"):
    """
    Signs a certificate request

    signingReq - The certificate request (crypto.X509Req)
    issuerSubject - The subject of the issuer (crypto.X509Name)
    issuerKey - The private key of the issuer
    notBefore - Timestamp (relative to now) when the certificate
    starts being valid
    notAfter - Timestamp (relative to now) when the certificate
    stops being valid
    extensions - extensions to set (as non critical){key:value/list with values}
    digest - Digest method to use for signing, default is md5
    Returns: The signed certificate in an X509 object
    """
    cert = crypto.X509()
    global serial

    x509v3 = 2
    cert.set_version(x509v3)
    cert.set_serial_number(serial)
    cert.gmtime_adj_notBefore(notBefore)
    cert.gmtime_adj_notAfter(notAfter)
    cert.set_issuer(issuerSubject)
    cert.set_subject(signingReq.get_subject())
    cert.set_pubkey(signingReq.get_pubkey())

    if extensions:
        for key, value in extensions.items():
            if isinstance(value, basestring):
                cert.add_extensions([crypto.X509Extension(key, False, value)])
            else:
                for subvalue in value:  # expect list
                    cert.add_extensions([crypto.X509Extension(key, False, subvalue)])

    cert.sign(issuerKey, digest)
    serial += 1
    return cert


def generate_ca(destfolder, **kwargs):
    """
        Generate a new CA key pair.

        **kwargs contains the subject of the CA certificate.
    """
    caKey = _generateKeyPair()
    caReq = _generateCertRequest(caKey, **kwargs)
    caCert = _signCertificateRequest(caReq, caReq.get_subject(), caKey, (0, 60 * 60 * 24 * 365 * 5))

    _store_certs(destfolder, caKey, caCert)
    return caKey, caCert


def generate_interm(destfolder, signer, **kwargs):
    """
        Generate new intermediate certificate and signs it by the given CA.

        **kwargs contains the subject of the new certificate.
    """
    intermKey = _generateKeyPair()
    intermReq = _generateCertRequest(intermKey, **kwargs)
    intermCert = _signCertificateRequest(intermReq, signer.get_certificate().get_subject(),
                                         signer.get_privatekey(),
                                         (0, 60 * 60 * 24 * 365 * 5))

    _store_certs(destfolder, intermKey, intermCert)
    return intermKey, intermCert


def _store_certs(destfolder, key, cert):
    for (k, v) in cert.get_subject().get_components():
        if k == "CN":
            commonName = v
            break
    p12 = crypto.PKCS12()
    p12.set_certificate(cert)
    p12.set_privatekey(key)
    open(os.path.join(destfolder, '%s.p12' % commonName), 'wb').write(p12.export(cert_password))


def main():
    #parser = optparse.OptionParser('usage %prog [Options]')
    #
    #parser.add_option("--cacert", dest="caCert", type="string",
    #                  help="The public part of the ROOT CA certificate to use")
    #parser.add_option("--cakey", dest="caKey", type="string", help="The private part of the ROOT CA certificate to use")
    #parser.add_option("--cakeypass", dest="caKeyPass", type="string",
    #                  help="The password for the private part of the ROOT CA certificate")
    #
    #parser.add_option("--intermcert", dest="intermCert", type="string",
    #                  help="The public part of the Intermediate CA certificate to use")
    #parser.add_option("--intermkey", dest="intermKey", type="string",
    #                  help="The private part of the Intermediate CA certificate to use")
    #parser.add_option("--intermkeypass", dest="intermKeyPass", type="string",
    #                  help="The password for the private part of the Intermediate CA certificate")
    #
    #parser.add_option("--cn", dest="commonname", type="string", help="The common name for the server certificate")
    #
    #parser.add_option("--san", dest="san", action="append", type="string",
    #                  help="A SAN for the server certificate. Must be prefixed with "
    #                       "OBJECT_IDENTIFIER: (e.g. DNS:google.com). Can be used multiple times")
    #
    #(options, args) = parser.parse_args()
    #if not options:
    #    parser.print_help()
    #    exit(1)
    #
    #if not options.caCert:
    #    # generate the entire chain
    #    caKey, caCert = generate_ca()
    #    intermKey, intermCert = generate_interm(caKey, caCert)
    #else:
    #    if options.caKeyPass:
    #        caKey, caCert = loadFromFile(options.caCert, options.caKey, options.caKeyPass)
    #    else:
    #        caKey, caCert = loadFromFile(options.caCert, options.caKey)
    #    if options.intermKeyPass:
    #        intermKey, intermCert = loadFromFile(options.intermCert, options.intermKey, options.intermKeyPass)
    #    else:
    #        intermKey, intermCert = loadFromFile(options.intermCert, options.intermKey)
    #
    #extensions = []
    #for san in options.san:
    #    extensions.append(san)
    #
    #pkey = generateKeyPair()
    #req = generateCertRequest(pkey, CN=options.commonname)
    #cert = signCertificateRequest(req, (intermCert, intermKey), 2, (0, 60 * 60 * 24 * 365 * 5), # five years
    #                              extensions={"subjectAltName": extensions})
    #open('sample/%s.key' % options.commonname, 'w').write(
    #    crypto.dump_privatekey(crypto.FILETYPE_PEM, pkey))
    #open('sample/%s.crt' % options.commonname, 'w').write(
    #    crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
    certs = loadcertificates("/home/makpoc/certs")
    print construct_chains(certs)


def construct_subject_from_component(component):
    subject = []
    for v in component:
        subject.append("=".join(v))
    return ", ".join(subject)


if __name__ == "__main__":
    main()
