package org.sigep.core.signs.certificado.util;


import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;

/**
 * Clase encargada de crear una instancia o fuente a partir de cualquier tipo de dato
 * (archivo, cadena de texto, numero).
 * Convierte la fuente en un array de bytes para ser procesados para las firmas.
 * @author Ronald Coarite
 */
public final class DataStream
{
    /**
     * Array de bytes de cualquier documento
     */
    private byte[] data;
    
    /**
     * Contructor que establece el array de datos
     * @param data El Array de datos
     */
    private DataStream(byte[] data)
    {
        this.data = data;
    }
    
    /**
     * Crea una instancia a partir de un array de datos
     * @param data El array de datos de un documento
     * @return Un DataStream a partir del array de bytes
     */
    public static DataStream load(byte data[])
    {
        DataStream source = new DataStream(data);
        return source;
    }
    
    /**
     * Crea una instancia a partir de un Flujo de Entrada con un tamaño específico
     * @param inputStream El flujo de entrada del documento
     * @param length El tamaño del documento
     * @return el DataStream del flujo de entrada
     * @throws IOException 
     */
    public static DataStream load(InputStream inputStream,long length) throws IOException
    {
        byte[] sig_Bytes = new byte[(int)length];
        DataInputStream in = new DataInputStream(inputStream);
        in.readFully(sig_Bytes);
        in.close();
        return load(sig_Bytes);
    }
    
//    public static DataStream load(String text)
//    {
//        return load(text.getBytes());
//    }
//    
//    public static DataStream load(String text,String encoding) throws UnsupportedEncodingException
//    {
//        return load(text.getBytes(encoding));
//    }
    
    /**
     * Crea una isntancia a partir de un archivo 
     * @param file El archivo o ruta del documento
     * @return El DataStrema del archivo
     * @throws IOException 
     */
    public static DataStream load(File file) throws IOException
    {
        if(!file.exists())
            throw new RuntimeException("El archivo ["+file.getAbsolutePath()+"] no existe");
        if(!file.canRead())
            throw new RuntimeException("Verfique permisos de lectura. No es posible leer el archivo");
        try
        {
            return load(new FileInputStream(file),file.length());
        }
        catch (FileNotFoundException e)
        {
            // NO DEBERIA LLEGAR ACA
        }
        throw new RuntimeException("Un error interno desconocido. Error al procesar el archivo ["+file.getAbsolutePath()+"]");
    }

    /**
     * Obtiene el array de datos del documento
     * @return Un Array de bytes del docuemnto
     */
    public byte[] getData()
    {
        return data;
    }
}