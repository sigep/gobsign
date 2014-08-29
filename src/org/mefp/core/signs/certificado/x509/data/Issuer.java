package org.mefp.core.signs.certificado.x509.data;

/**
 * Clase que representa al Emisor del certificado
 * @author rcoarite
 */
public class Issuer
{
    /**
     * Nombre comercial de entidad certificadora autorizada
     * CN
     */
    private String name;
    
    /**
     * Razon social de la entidad cerficadora actualizada
     * O
     */
    private String socialReason;
    
    /**
     * Country es el país de la ubicación del emisor
     *  según estandar de acuerdo a la ISO 3176
     * C
     */
    private String country="";

    /**
     * Constructor que inicializa los atributos con sus valores
     * @param name El nombre del emisor
     * @param socialReason La razon social
     * @param country  Es el país de la ubicación del emisor
     */
    public Issuer(String name, String socialReason, String country)
    {
        this.name = name;
        this.socialReason = socialReason;
        this.country= country;
    }

    /**
     * Constructor por defecto. Este constructor no inicializa ni un valor en sus
     * atrubutos
     */
    public Issuer() {
    }
    
    /**
     * Obtiene el nombre del emisor
     * @return Nombre del emisor
     */
    public String getName() {
        return name;
    }

    /**
     * Establece el nombre del emisor
     * @param name El nombre del emisor
     */
    public void setName(String name) {
        this.name = name;
    }

    /**
     * Obtiene el nombre de la razon social
     * @return La razon social
     */
    public String getSocialReason() {
        return socialReason;
    }

    /**
     * Estable el nombre de la razon social
     * @param socialReason La razon social
     */
    public void setSocialReason(String socialReason) {
        this.socialReason = socialReason;
    }

    public String getCountry() {
        return country;
    }

    public void setCountry(String country) {
        this.country = country;
    }

    
    

    /**
     * Retorna una representacion en cadena con todos sus atributos
     * @return Un String con la representacion del objeto
     */
    @Override
    public String toString() {
        return "Issuer{" + "name=" + name + ", socialReason=" + socialReason + ", country=" + country + '}';
    }
}