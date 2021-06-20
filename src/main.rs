/// file: main.rs
use concrete_lib::*;
use std::time::{Duration, Instant};

fn encrypt_decrypt(iterations : usize) -> Result<(), CryptoAPIError> {
    let mut duration_key_vec : Vec<f64> = Vec::new();
    let mut duration_encryption_vec : Vec<f64> = Vec::new();
    let mut duration_decryption_vec : Vec<f64> = Vec::new();
    let mut duration_complete_vec : Vec<f64> = Vec::new();
    let mut error_complete_vec : Vec<f64> = Vec::new();

    for index in 0..iterations{
        // println!("\n\nPRIMERA IMPLEMENTACIÓN: cifrado y descifrado \n");
        let start_key = Instant::now(); // Comenzar temporizador
        let secret_key = LWESecretKey::new(&LWE128_1024); // Generar clave de cifrado
        let duration_key = start_key.elapsed(); // Finalizar temporizador
        duration_key_vec.push(duration_key.as_secs_f64());

        // a list of messages
        let messages: Vec<f64> = vec![-6.276, 4.3, 0.12, -1.1, 7.78]; // Vector de mensajes
        // println!("Mensaje original: {:?}", messages);

        secret_key.save("my_very_secret_key.json"); // Función para guardar la clave en un archivo .json

        let start_encryption = Instant::now(); // Comenzar temporizador
        // create an encoder
        let encoder = Encoder::new(-10., 10., 8, 0)?; // Generar encoder para crear plaintext

        // encode and encrypt message vector
        let ciphertext = VectorLWE::encode_encrypt(&secret_key, &messages, &encoder)?; // Codificar y generar texto cifrado a partir del encoder y la clave generada
        let duration_encryption = start_encryption.elapsed(); // Finalizar temporizador
        duration_encryption_vec.push(duration_encryption.as_secs_f64());

        let start_decryption = Instant::now(); // Comenzar temporizador
        // decrypt
        let outputs: Vec<f64> = ciphertext.decrypt_decode(&secret_key)?; // Descifrar mensaje
        let duration_decryption = start_decryption.elapsed(); // Finalizar temporizador
        duration_decryption_vec.push(duration_decryption.as_secs_f64());
        duration_complete_vec.push(start_key.elapsed().as_secs_f64());

        // Calcular error de cada elemento
        let mut error_vec : Vec<f64> = Vec::new();
        for (index, element) in outputs.iter().enumerate(){
            error_vec.push((element - messages[index]).abs()/(messages[index]));
        }

        // Calcular error medio del mensaje
        let mut sum : f64 = 0.;
        for (index, element) in error_vec.iter().enumerate(){
            sum = sum + element;
        }
        error_complete_vec.push(sum/(error_vec.len() as f64));
    }

    let mut encrypt_sum : f64 = 0.;
    let mut key_sum : f64 = 0.;
    let mut decrypt_sum : f64 = 0.;
    let mut complete_sum : f64 = 0.;
    let mut error_sum : f64 = 0.;

    // Calcular la media de todas las iteraciones
    for index in 0..iterations{
        encrypt_sum = duration_encryption_vec[index] + encrypt_sum;
        decrypt_sum = duration_decryption_vec[index] + decrypt_sum;
        key_sum = duration_key_vec[index] + key_sum;
        complete_sum = duration_complete_vec[index] + complete_sum;
        error_sum = error_complete_vec[index] + error_sum;
    }

    let iterations_f64 : f64 = iterations as f64;
    let average_encrypt : f64 = encrypt_sum / iterations_f64.clone();
    let average_decrypt : f64 = decrypt_sum / iterations_f64.clone();
    let average_key : f64 = key_sum / iterations_f64.clone();
    let average_complete : f64 = complete_sum / iterations_f64.clone();
    let average_error : f64 = error_sum / iterations_f64.clone();

    println!("/ RESULTS /");
    println!("Encrypt average: {:?}s", average_encrypt);
    println!("Decrypt average: {:?}s", average_decrypt);
    println!("Key Generation average: {:?}s", average_key);
    println!("Execution average: {:?}s", average_complete);
    println!("Average messages error: {:?}%", average_error * 100.);
    return Ok(());
}

fn key_switching(iterations : usize) -> Result<(), CryptoAPIError> {
    let mut duration_key_vec : Vec<f64> = Vec::new();
    let mut duration_encryption1_vec : Vec<f64> = Vec::new();
    let mut duration_encryption2_vec : Vec<f64> = Vec::new();
    let mut duration_decryption_vec : Vec<f64> = Vec::new();
    let mut duration_complete_vec : Vec<f64> = Vec::new();
    let mut error_complete_vec : Vec<f64> = Vec::new();

    for index in 0..iterations{

        // println!("\n //////////////////////////////////// \n");
        // println!("SEGUNDA IMPLEMENTACIÓN: Key Switching \n");
        let start_key = Instant::now(); // Comenzar temporizador
        // encoder
        let encoder = Encoder::new(100., 110., 5, 0)?;

        // generate two secret keys
        let secret_key_before = LWESecretKey::new(&LWE128_1024); // Clave (1). Generar clave de cifrado
        let secret_key_after = LWESecretKey::new(&LWE128_630); // Clave (2). Generar clave de descifrado (segunda clave)

        // generate the key switching key
        let ksk = crypto_api::LWEKSK::new(&secret_key_before, &secret_key_after, 2, 6); // Clave (3). A partir de las dos claves generadas anteriormente, se genera la clave que va a permitir realizar el cambio de clave de cifrado.
        let duration_key = start_key.elapsed();// Finalizar temporizador
        duration_key_vec.push(duration_key.as_secs_f64());

        // El mensaje original se cifra utilizando la Clave (1). A continuación, el mensaje cifrado se vuelve a cifrar con la Clave (3). El mensaje cifrado resultante solo se puede descifrar con Clave (2).

        // a list of messages that we encrypt
        let messages: Vec<f64> = vec![106.276, 104.3, 100.12, 101.1, 107.78]; // Vector de mensajes
        // println!("Mensaje original: {:?}", messages);

        let start_encryption1 = Instant::now(); // Comenzar temporizador
        let ciphertext_before = VectorLWE::encode_encrypt(&secret_key_before, &messages, &encoder)?; // Cifrar el mensaje original con Clave (1).
        let duration_encryption1 = start_encryption1.elapsed(); // Finalizar temporizador
        duration_encryption1_vec.push(duration_encryption1.as_secs_f64());

        let start_encryption2 = Instant::now(); // Comenzar temporizador
        // key switch
        let ciphertext_after = ciphertext_before.keyswitch(&ksk); // Cifrar el mensaje cifrado con Clave (3).
        let duration_encryption2 = start_encryption2.elapsed(); // Finalizar temporizador
        duration_encryption2_vec.push(duration_encryption2.as_secs_f64());

        let start_decryption = Instant::now(); // Comenzar temporizador
        // decryption
        let outputs: Vec<f64> = ciphertext_before.decrypt_decode(&secret_key_before)?; // Descifrar el mensaje cifrado resultante con la Clave (2).
        // println!("Output: {:?}", outputs);
        let duration_decryption = start_decryption.elapsed(); // Finalizar temporizador
        duration_decryption_vec.push(duration_decryption.as_secs_f64());
        duration_complete_vec.push(start_key.elapsed().as_secs_f64());

        // Calcular error de cada elemento
        let mut error_vec : Vec<f64> = Vec::new();
        for (index, element) in outputs.iter().enumerate(){
            error_vec.push((element - messages[index]).abs()/(messages[index]));
        }

        // println!("Error {:?}", error_vec);

        // Calcular error medio del mensaje
        let mut sum : f64 = 0.;
        for (index, element) in error_vec.iter().enumerate(){
            sum = sum + element;
        }
        error_complete_vec.push(sum/(error_vec.len() as f64));
    }

    // println!("Complete error: {:?}", error_complete_vec);

    let mut encrypt1_sum : f64 = 0.;
    let mut encrypt2_sum : f64 = 0.;
    let mut key_sum : f64 = 0.;
    let mut decrypt_sum : f64 = 0.;
    let mut complete_sum : f64 = 0.;
    let mut error_sum : f64 = 0.;

    // Calcular la media de todas las iteraciones
    for index in 0..iterations{
        encrypt1_sum = duration_encryption1_vec[index] + encrypt1_sum;
        encrypt2_sum = duration_encryption2_vec[index] + encrypt2_sum;
        decrypt_sum = duration_decryption_vec[index] + decrypt_sum;
        key_sum = duration_key_vec[index] + key_sum;
        complete_sum = duration_complete_vec[index] + complete_sum;
        error_sum = error_complete_vec[index] + error_sum;
    }

    let iterations_f64 : f64 = iterations as f64;
    let average_encrypt1 : f64 = encrypt1_sum / iterations_f64.clone();
    let average_encrypt2 : f64 = encrypt2_sum / iterations_f64.clone();
    let average_decrypt : f64 = decrypt_sum / iterations_f64.clone();
    let average_key : f64 = key_sum / iterations_f64.clone();
    let average_complete : f64 = complete_sum / iterations_f64.clone();
    let average_error : f64 = error_sum / iterations_f64.clone();

    println!("/ RESULTS /");
    println!("Encrypt 1 average: {:?}s", average_encrypt1);
    println!("Encrypt 2 average: {:?}s", average_encrypt2);
    println!("Decrypt average: {:?}s", average_decrypt);
    println!("Key Generation average: {:?}s", average_key);
    println!("Execution average: {:?}s", average_complete);
    println!("Average messages error: {:?}%", average_error * 100.);
    return Ok(());
}

fn sum_of_constants(iterations : usize) -> Result<(), CryptoAPIError> {
    let mut duration_key_vec : Vec<f64> = Vec::new();
    let mut duration_encryption_vec : Vec<f64> = Vec::new();
    let mut duration_sum_vec : Vec<f64> = Vec::new();
    let mut duration_decryption_vec : Vec<f64> = Vec::new();
    let mut duration_complete_vec : Vec<f64> = Vec::new();
    let mut error_complete_vec : Vec<f64> = Vec::new();

    for index in 0..iterations{
        // println!("\n //////////////////////////////////// \n");
        // println!("TERCERA IMPLEMENTACIÓN: Operaciones Homomórficas (Leveled Operations) \n");

        // println!("--- Sumar un vector de contantes a un mensaje cifrado ---\n");

        // generate a secret key
        let start_key = Instant::now(); // Comenzar temporizador
        let secret_key = LWESecretKey::new(&LWE128_1024); // Generar clave de cifrado
        let duration_key = start_key.elapsed(); // Finalizar temporizador
        duration_key_vec.push(duration_key.as_secs_f64());

        let messages: Vec<f64> = vec![106.276, 104.3, 100.12, 101.1, 107.78];
        let constants: Vec<f64> = vec![-4.9, 1.02, 4.6, 5.6, -3.2];

        // encoder
        let start_encryption = Instant::now(); // Comenzar temporizador
        let encoder = Encoder::new(100., 210., 8, 0)?;
        // encrypt
        let mut ciphertext_vector = VectorLWE::encode_encrypt(&secret_key, &messages, &encoder)?;
        let duration_encryption = start_encryption.elapsed(); // Finalizar temporizador
        duration_encryption_vec.push(duration_encryption.as_secs_f64());

        // addition between ciphertexts and constants
        let start_addition = Instant::now(); // Comenzar temporizador
        ciphertext_vector.add_constant_dynamic_encoder_inplace(&constants)?;
        let duration_addition = start_addition.elapsed(); // Finalizar temporizador
        duration_sum_vec.push(duration_addition.as_secs_f64());

        // decryption
        let start_decryption = Instant::now(); // Comenzar temporizador
        let outputs: Vec<f64> = ciphertext_vector.decrypt_decode(&secret_key)?;
        let duration_decryption = start_decryption.elapsed(); // Finalizar temporizador
        duration_decryption_vec.push(duration_decryption.as_secs_f64());
        duration_complete_vec.push(start_key.elapsed().as_secs_f64());

        // Calcular resultado sin error
        let mut sum_real_result : Vec<f64> = Vec::new();
        for (index, element) in messages.iter().enumerate(){
            sum_real_result.push(element + constants[index]);
        }

        // Calcular error de cada elemento
        let mut error_vec : Vec<f64> = Vec::new();
        for (index, element) in outputs.iter().enumerate(){
            error_vec.push((element - sum_real_result[index]).abs()/(sum_real_result[index]));
        }

        // Calcular error medio del mensaje
        let mut sum : f64 = 0.;
        for (index, element) in error_vec.iter().enumerate(){
            sum = sum + element;
        }
        error_complete_vec.push(sum/(error_vec.len() as f64));
    }

    let mut encrypt_sum : f64 = 0.;
    let mut addition_sum : f64 = 0.;
    let mut key_sum : f64 = 0.;
    let mut decrypt_sum : f64 = 0.;
    let mut complete_sum : f64 = 0.;
    let mut error_sum : f64 = 0.;

    // Calcular la media de todas las iteraciones
    for index in 0..iterations{
        encrypt_sum = duration_encryption_vec[index] + encrypt_sum;
        addition_sum = duration_sum_vec[index] + addition_sum;
        decrypt_sum = duration_decryption_vec[index] + decrypt_sum;
        key_sum = duration_key_vec[index] + key_sum;
        complete_sum = duration_complete_vec[index] + complete_sum;
        error_sum = error_complete_vec[index] + error_sum;
    }

    let iterations_f64 : f64 = iterations as f64;
    let average_encrypt: f64 = encrypt_sum / iterations_f64.clone();
    let average_sum: f64 = addition_sum / iterations_f64.clone();
    let average_decrypt : f64 = decrypt_sum / iterations_f64.clone();
    let average_key : f64 = key_sum / iterations_f64.clone();
    let average_complete : f64 = complete_sum / iterations_f64.clone();
    let average_error : f64 = error_sum / iterations_f64.clone();

    println!("/ RESULTS /");
    println!("Encrypt average: {:?}s", average_encrypt);
    println!("Sum average: {:?}s", average_sum);
    println!("Decrypt average: {:?}s", average_decrypt);
    println!("Key Generation average: {:?}s", average_key);
    println!("Execution average: {:?}s", average_complete);
    println!("Average messages error: {:?}%", average_error * 100.);
    return Ok(());
}

fn sum_of_ciphertexts(iterations : usize) -> Result<(), CryptoAPIError> {
    let mut duration_key_vec : Vec<f64> = Vec::new();
    let mut duration_encryption_vec : Vec<f64> = Vec::new();
    let mut duration_sum_vec : Vec<f64> = Vec::new();
    let mut duration_decryption_vec : Vec<f64> = Vec::new();
    let mut duration_complete_vec : Vec<f64> = Vec::new();
    let mut error_complete_vec : Vec<f64> = Vec::new();

    for index in 0..iterations{

        // println!("--- Sumar mensajes cifrados ---\n");

        // generate a secret key
        let start_key = Instant::now(); // Comenzar temporizador
        let secret_key = LWESecretKey::new(&LWE128_630); // Generar clave de cifrado
        let duration_key = start_key.elapsed(); // Finalizar temporizador
        duration_key_vec.push(duration_key.as_secs_f64());

        // message vectors to add
        let mv1: Vec<f64> = vec![1.2, 4.3, 0.11, 3.1, 6.7];
        let mv2: Vec<f64> = vec![7.0, 1.0, 8.2, 3.7, 9.4];

        // Encode in [0, 10[ with 8 bits of precision and 1 bit of padding
        let start_encryption = Instant::now(); // Comenzar temporizador
        let encoder = Encoder::new(0., 10., 8, 1)?;
        // encode encrypt
        let mut cv1 = VectorLWE::encode_encrypt(&secret_key, &mv1, &encoder)?;
        let cv2 = VectorLWE::encode_encrypt(&secret_key, &mv2, &encoder)?;
        let duration_encryption = start_encryption.elapsed(); // Finalizar temporizador
        duration_encryption_vec.push(duration_encryption.as_secs_f64());

        // add ciphertext vectors element-wise
        let start_addition = Instant::now(); // Comenzar temporizador
        cv1.add_with_padding_inplace(&cv2)?;
        let duration_addition = start_addition.elapsed(); // Finalizar temporizador
        duration_sum_vec.push(duration_addition.as_secs_f64());

        // decryption
        let start_decryption = Instant::now(); // Comenzar temporizador
        let outputs: Vec<f64> = cv1.decrypt_decode(&secret_key)?;
        let duration_decryption = start_decryption.elapsed(); // Finalizar temporizador
        duration_decryption_vec.push(duration_decryption.as_secs_f64());
        duration_complete_vec.push(start_key.elapsed().as_secs_f64());

        // Calcular resultado sin error
        let mut sum_real_result : Vec<f64> = Vec::new();
        for (index, element) in mv1.iter().enumerate(){
            sum_real_result.push(element + mv2[index]);
        }

        // Calcular error de cada elemento
        let mut error_vec : Vec<f64> = Vec::new();
        for (index, element) in outputs.iter().enumerate(){
            error_vec.push((element - sum_real_result[index]).abs()/(sum_real_result[index]));
        }

        // Calcular error medio del mensaje
        let mut sum : f64 = 0.;
        for (index, element) in error_vec.iter().enumerate(){
            sum = sum + element;
        }
        error_complete_vec.push(sum/(error_vec.len() as f64));
    }

    let mut encrypt_sum : f64 = 0.;
    let mut addition_sum : f64 = 0.;
    let mut key_sum : f64 = 0.;
    let mut decrypt_sum : f64 = 0.;
    let mut complete_sum : f64 = 0.;
    let mut error_sum : f64 = 0.;

    // Calcular la media de todas las iteraciones
    for index in 0..iterations{
        encrypt_sum = duration_encryption_vec[index] + encrypt_sum;
        addition_sum = duration_sum_vec[index] + addition_sum;
        decrypt_sum = duration_decryption_vec[index] + decrypt_sum;
        key_sum = duration_key_vec[index] + key_sum;
        complete_sum = duration_complete_vec[index] + complete_sum;
        error_sum = error_complete_vec[index] + error_sum;
    }

    let iterations_f64 : f64 = iterations as f64;
    let average_encrypt: f64 = encrypt_sum / iterations_f64.clone();
    let average_sum: f64 = addition_sum / iterations_f64.clone();
    let average_decrypt : f64 = decrypt_sum / iterations_f64.clone();
    let average_key : f64 = key_sum / iterations_f64.clone();
    let average_complete : f64 = complete_sum / iterations_f64.clone();
    let average_error : f64 = error_sum / iterations_f64.clone();

    println!("/ RESULTS /");
    println!("Encrypt average: {:?}s", average_encrypt);
    println!("Sum average: {:?}s", average_sum);
    println!("Decrypt average: {:?}s", average_decrypt);
    println!("Key Generation average: {:?}s", average_key);
    println!("Execution average: {:?}s", average_complete);
    println!("Average messages error: {:?}%", average_error * 100.);
    return Ok(());
}

fn mul_of_constants(iterations : usize) -> Result<(), CryptoAPIError> {
    return Ok(());
}

fn main() -> Result<(), CryptoAPIError> {

    let iterations : usize = 100;

    println!("PRIMERA IMPLEMENTACIÓN: Cifrado y descifrado de un mensaje");
    println!("Trabajando...");
    encrypt_decrypt(iterations.clone());

    println!("\n\nSEGUNDA IMPLEMENTACIÓN: Key Switching");
    println!("Trabajando...");
    key_switching(iterations.clone());

    println!("\n\nTERCERA IMPLEMENTACIÓN: Suma de constantes y mensaje cifrado");
    println!("Trabajando...");
    sum_of_constants(iterations.clone());

    println!("\n\nCUARTA IMPLEMENTACIÓN: Suma de mensajes cifrados");
    println!("Trabajando...");
    sum_of_ciphertexts(iterations.clone());

    println!("\n\nQUINTA IMPLEMENTACIÓN: Multiplicación de constantres y un mensaje cifrado");
    println!("Trabajando...");
    mul_of_constants(iterations.clone());

/*
    //////////////////////////////////////////////////////////////////////////////////7

    println!("--- Multiplicar un vector de constantes por un mensaje cifrado ---\n");

    // generate a secret key
    let start_key = Instant::now(); // Comenzar temporizador
    let secret_key = LWESecretKey::new(&LWE128_1024); // Generar clave de cifrado
    let duration_key = start_key.elapsed(); // Finalizar temporizador

    let messages: Vec<f64> = vec![6.1, 5.4, -2.7];
    let constants: Vec<i32> = vec![-4, 5, 3];

    // encoder
    let start_encryption = Instant::now(); // Comenzar temporizador
    let encoder = Encoder::new(-30., 30., 8, 0)?;
    let mut ciphertext_vector = VectorLWE::encode_encrypt(&secret_key, &messages, &encoder)?;
    let duration_encryption = start_encryption.elapsed(); // Finalizar temporizador

    // vector multiplication between ciphertext and constants
    let start_mult = Instant::now(); // Comenzar temporizador
    ciphertext_vector.mul_constant_static_encoder_inplace(&constants)?;
    let duration_mult = start_mult.elapsed(); // Finalizar temporizador

    // decryption
    let start_decryption = Instant::now(); // Comenzar temporizador
    let outputs: Vec<f64> = ciphertext_vector.decrypt_decode(&secret_key)?;
    let duration_decryption = start_decryption.elapsed(); // Finalizar temporizador


    // Resultados finales
    println!("Mensaje original: {:?}", messages);
    println!("Vector de constantes: {:?}", constants);
    println!("Mensaje descifrado: {:?}\n", outputs);
    println!("Tiempo generando claves: {:?}", duration_key);
    println!("Tiempo de cifrado 1: {:?}", duration_encryption);
    println!("Tiempo transcurrido en la multiplicación: {:?}", duration_mult);
    println!("Tiempo de descifrado: {:?}", duration_decryption);
    println!("Tiempo de ejecución total: {:?}\n\n", start_key.elapsed());


    //////////////////////////////////////////////////////////////////////////////////

    println!("\n //////////////////////////////////// \n");
    println!("CUARTA IMPLEMENTACIÓN: Bootstrapping \n");
    // encoders
    let start_key = Instant::now();
    let encoder_input = Encoder::new(-10., 10., 6, 1)?;
    let encoder_output = Encoder::new(0., 101., 6, 0)?;

    // secret keys
    let sk_rlwe = RLWESecretKey::new(&RLWE128_1024_1);
    let sk_in = LWESecretKey::new(&LWE128_630);
    let sk_out = sk_rlwe.to_lwe_secret_key();

    // bootstrapping key
    let bsk = LWEBSK::new(&sk_in, &sk_rlwe, 5, 3);
    let duration_key = start_key.elapsed();



    // messages
    let message: f64 = -5.;
    println!("Mensaje original: {:?}", message);



    // encode and encrypt
    let start_encryption1 = Instant::now();
    let c1 = LWE::encode_encrypt(&sk_in, message, &encoder_input)?;
    let duration_encryption1 = start_encryption1.elapsed();

    // bootstrap
    let start_encryption2 = Instant::now();
    let c2 = c1.bootstrap(&bsk)?;
    let duration_encryption2 = start_encryption2.elapsed();

    // decrypt
    let start_decryption = Instant::now();
    let output = c2.decrypt_decode(&sk_out)?;
    let duration_decryption = start_decryption.elapsed();

    println!("before bootstrap: {}, after bootstrap: {}", message, output);

    println!("Mensaje descifrado: {:?}", output);
    println!("Tiempo generando claves: {:?}", duration_key);
    println!("Tiempo de cifrado: {:?}", duration_encryption1);
    println!("Tiempo de Bootstrapping: {:?}", duration_encryption2);
    println!("Tiempo de descifrado: {:?}", duration_decryption);
    println!("Tiempo de ejecución total: {:?}", start_key.elapsed());
    */

    Ok(())
}
