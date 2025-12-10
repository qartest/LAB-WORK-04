package boev.work;

import java.io.*;
import java.nio.file.AccessDeniedException;
import java.nio.file.NoSuchFileException;
import static java.lang.System.exit;

public class Main {
    private static final int SIZE_BUFFER = 1024;
    public static void main(String[] args) {

        if(args.length != 4){
            System.out.println("Программа не может работать. Неправильный ввод");
            exit(1);
        }

        if(args[0].equals("0")){
            try(BufferedInputStream in = new BufferedInputStream(new FileInputStream(args[1]));
                BufferedOutputStream out = new BufferedOutputStream(new FileOutputStream(args[2]));
                BufferedOutputStream key = new BufferedOutputStream(new FileOutputStream(args[3]))) {

                byte[] inputBuffer = new byte[SIZE_BUFFER];
                byte[] outputBuffer = new byte[SIZE_BUFFER];
                byte[] keyBuffer = new byte[SIZE_BUFFER];

                StringBuilder stringBuilder = new StringBuilder();
                int sizeRead = 0;
                System.out.println("Шифрование");

                while((sizeRead = in.read(inputBuffer)) > 0){
                    getKey(keyBuffer);

                    for(int i = 0; i < sizeRead; ++i){
                        outputBuffer[i] = (byte)(inputBuffer[i] ^ keyBuffer[i]);
                    }

                    key.write(keyBuffer, 0, sizeRead);
                    out.write(outputBuffer, 0, sizeRead);


                }
            } catch (NoSuchFileException e){
                System.out.println("Такого файла нет: " + e.getFile());
            }catch (AccessDeniedException e) {
                System.out.println("Нет прав: " + e.getFile());
            } catch (IOException e) {
                System.out.println("Общая ошибка I/O: " + e.getMessage());
            }
        }else if(args[0].equals("1")){
            try(BufferedInputStream in = new BufferedInputStream(new FileInputStream(args[1]));
                BufferedOutputStream out = new BufferedOutputStream(new FileOutputStream(args[2]));
                BufferedInputStream key = new BufferedInputStream(new FileInputStream(args[3]))){

                byte[] inputBuffer = new byte[SIZE_BUFFER];
                byte[] outputBuffer = new byte[SIZE_BUFFER];
                byte[] keyBuffer = new byte[SIZE_BUFFER];

                int sizeRead = 0;

                System.out.println("Дешифрование");

                while((sizeRead = in.read(inputBuffer)) > 0){
                    key.read(keyBuffer, 0, sizeRead);
                    for(int i = 0; i < sizeRead; ++i){
                        outputBuffer[i] = (byte)(inputBuffer[i] ^ keyBuffer[i]);
                    }
                    out.write(outputBuffer, 0, sizeRead);
                }

            }catch (NoSuchFileException e){
                System.out.println("Такого файла нет: " + e.getFile());
            }catch (AccessDeniedException e){
                System.out.println("Нет прав: " + e.getFile());
            } catch (IOException e){
                System.out.println("Общая ошибка I/O: " +  e.getMessage());
            }
        }else{
            System.out.println("Программа не может работать. Неправильный первый аргумент");
            exit(1);
        }

    }

    public static void getKey(byte[] buffer){
        new java.security.SecureRandom().nextBytes(buffer);
    }
}