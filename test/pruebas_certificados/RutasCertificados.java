package pruebas_certificados;

/**
 *
 * @author rcoarite
 */
public interface RutasCertificados
{
    public static final String RUTA_CERTIFICADO_PUBLICO_RAIZ = "c:\\llaves\\certificado_publico_raiz.cer";
    public static final String RUTA_CERTIFICADO_PUBLICO_ENTIDAD = "c:\\llaves\\certificado_publico_entidad.cer";
    public static final String RUTA_CERTIFICADO_PRIVADO_RAIZ = "c:\\llaves\\certificado_privado_raiz.p12";
    public static final String RUTA_CERTIFICADO_PRIVADO_ENTIDAD = "c:\\llaves\\certificado_privado_entidad.p12";
    public static final String CLAVE_DE_CERTIFICADO_PRIVADO = "clavesecreta";
    public static final String DOCUMENTO_PARA_FIRMAR = "c:\\llaves\\mensajefirmado.txt";
    public static final String DOCUMENTO_FIRMADO = "c:\\llaves\\mensajefirmado.txt.sig";
}
