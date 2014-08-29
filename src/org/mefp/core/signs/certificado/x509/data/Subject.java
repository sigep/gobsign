package org.mefp.core.signs.certificado.x509.data;

import java.math.BigDecimal;

/**
 * Clase que representa al suscriptor del certificado para la llave pública 
 * @author rcoarite
 */
public class Subject
{
    /**
     * Nombre completo de la persona natural
     * CN
     */
    private String name;
    
    /**
     * Pais emisor del documento presentado (ISO 3166)
     * C
     */
    private String country;
    
    /**
     * Tipo y número de documento
     * SN
     */
    private BigDecimal serialNumber;
    
    /**
     * Correo electrónico
     * E
     */
    private String email;

    /**
     * Constructor que inicializar los atributos
     * @param name El nombre del Suscriptor
     * @param country El país del Suscriptor
     * @param serialNumber El número de serie del suscriptor
     * @param email El correo electrónico del suscriptor
     */
    public Subject(String name, String country, BigDecimal serialNumber, String email) {
        this.name = name;
        this.country = country;
        this.serialNumber = serialNumber;
        this.email = email;
    }

    /**
     * Constructor por defecto. Este constructor no inicializa ni un atributo
     */
    public Subject() {
    }

    /**
     * Obtiene el nombre del suscriptor
     * @return El nombre del suscriptor
     */
    public String getName() {
        return name;
    }

    /**
     * Establece el nombre del suscriptor
     * @param name Nombre del Suscriptor
     */
    public void setName(String name) {
        this.name = name;
    }

    /**
     * Obtiene el país del suscriptor
     * @return País del suscriptor
     */
    public String getCountry() {
        return country;
    }

    /**
     * Establece el país del sucriptor
     * @param country El país del suscriptor
     */
    public void setCountry(String country) {
        this.country = country;
    }

    /**
     * Obtiene el número de serie del suscriptor
     * @return El número de serie
     */
    public BigDecimal getSerialNumber() {
        return serialNumber;
    }

    /**
     * Establece el número de serie 
     * @param serialNumber El número de serie
     */
    public void setSerialNumber(BigDecimal serialNumber) {
        this.serialNumber = serialNumber;
    }
    
    /**
     * Establece el número de serie
     * @param serial El número de serie
     */
    public void setSerialNumber(long serial)
    {
        this.serialNumber = new BigDecimal(serial);
    }

    /**
     * Obtiene el nombre del correo electrónico
     * @return Un String con el Correo electrónico
     */
    public String getEmail() {
        return email;
    }

    /**
     * Establece el correo electrónico
     * @param email El Correo electrónico 
     */
    public void setEmail(String email) {
        this.email = email;
    }
    
    /**
     * Retorna una representación en cadena de objeto
     * @return Un String con la representación del objeto
     */
    @Override
    public String toString() {
        return "Subject{" + "name=" + name + ", country=" + country + ", serialNumber=" + serialNumber + ", email=" + email + '}';
    }
}
