package pruebas_certificados;

/**
 *
 * @author rcoarite
 */
public interface RutasCertificados
{
    public static final String RUTA_CERTIFICADO_PUBLICO_RAIZ = "E:\\llaves\\certificado_publico_raiz.cer";
    public static final String RUTA_CERTIFICADO_PUBLICO_ENTIDAD = "E:\\llaves\\certificado_publico_entidad.cer";
    public static final String RUTA_CERTIFICADO_PRIVADO_RAIZ = "E:\\llaves\\certificado_privado_raiz.p12";
    public static final String RUTA_CERTIFICADO_PRIVADO_ENTIDAD = "E:\\llaves\\certificado_privado_entidad.p12";
    public static final String CLAVE_DE_CERTIFICADO_PRIVADO = "clavesecreta";
    public static final String DOCUMENTO_PARA_FIRMAR = "E:\\llaves\\documento_prueba\\solo_texto.txt";
    public static final String DOCUMENTO_FIRMADO = "E:\\llaves\\documento_prueba\\solo_texto.txt.sig";
}
