package org.mefp.core.signs.certificado.util;

/**
 * Interfaz de constantes para la creación de firmas
 * @author rcoarite
 */
public interface Properties
{
    /**
     * El nombre del provehedor para BouncyCastle
     */
    public static final String BOUNCY_CASTLE_NAME_PROVIDER = "BC";
    /**
     * El tamaño de la firma
     */
    public static final int KEY_SIZE = 2048;
    
    //private static final String ENCODER_NAME = "SHA1withRSA";SHA256withRSA
    public static final String ENCODER_NAME = "SHA256withRSA";
    
    /** 
     * Estandar de codificacion para las firmas
     */
    public static final String CERTIFICATE_TYPE = "X.509";
    
    /**
     * El alias para el registro de la llave privada y publica en certificados p12
     */
    public static final String ALIAS_KEY = "key_alias";
}