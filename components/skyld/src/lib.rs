#![no_std]

// Based on ISO IEC 7816-4

use apdu_app::App as ApduApp;
use apdu_app::Interface;
use core::mem::size_of;
use half::f16;
use libm::scalbnf; // == ldexp
use heapless::Vec;
use heapless::VecView;
use iso7816::aid::App as AidApp;
use iso7816::{command::CommandView, Aid, Status};
use trussed_core::syscall;
use trussed_core::CryptoClient;

const MAX_KEYS: usize = 8;
const MAX_KEY_LEN: usize = 10240; // 10Ko

const F32_SIZE: usize = size_of::<f32>();
const F16_SIZE: usize = size_of::<half::f16>();

const QUANTIFICATION_FLOAT16: u8 = 0;
const QUANTIFICATION_FLOAT32: u8 = 1;

type SkyldKey = Vec<u8, MAX_KEY_LEN>;
type Random = Vec<u8, MAX_KEY_LEN>;

pub struct ProtectedModels {
    activation_key: SkyldKey,
    random: Random, // TODO : remove when future KDF will be input dependant
    quantification: u8,
}

pub struct SkyldApp<C> {
    trussed: C,
    protected_models: Vec<ProtectedModels, MAX_KEYS>,
    buff_reply: SkyldKey, // Because ADPU may not be able to return all the session key in one transfer
}

impl<C> SkyldApp<C> {
    // RID propriétaire 'F0' (see Table 90 in the ISO) suivi de l'identifiant "Skyld"
    const AID: Aid = Aid::new(&[0xF0, 0x53, 0x6B, 0x79, 0x6C, 0x64]);

    pub fn new(trussed: C) -> Self {
        Self {
            trussed,
            protected_models: Vec::new(),
            buff_reply: SkyldKey::new(),
        }
    }
}

// La logique de dérivation est ici
impl<C: CryptoClient> SkyldApp<C> {
    fn get_randoms(&mut self, bytes_key_size: usize, quantification: u8, random: &mut Random) -> Result<(), ()> {
        let reply = syscall!(self.trussed.random_bytes(bytes_key_size)); // TRNG
        let raw_random = &reply.bytes[..bytes_key_size];

        for chunk in raw_random.chunks_exact(size_of::<u32>()) {
            let mut bits = u32::from_ne_bytes(chunk.try_into().unwrap());

            match quantification {
                QUANTIFICATION_FLOAT16 => {
                    let index = bits % 16;
                    let exponent = (index as i32) - 6;
                    
                    let random_val_f32 = scalbnf(1.0, exponent);
                    
                    // Final cast
                    let random_val_f16 = f16::from_f32(random_val_f32);
                    random.extend_from_slice(&random_val_f16.to_ne_bytes()).map_err(|_| ())?;
                }

                _ => {
                    let mut random_val_f64: f64; // f64 = double
                    
                    loop {
                        random_val_f64 = (bits as f64 / u32::MAX as f64) * 2.0 - 1.0;
                        
                        if random_val_f64 != 0.0 {
                            break;
                        }
                        
                        let rep = syscall!(self.trussed.random_bytes(4));
                        bits = u32::from_ne_bytes(rep.bytes[..4].try_into().unwrap());
                    }

                    // Final cast
                    let random_val_f32 = random_val_f64 as f32;
                    random.extend_from_slice(&random_val_f32.to_ne_bytes()).map_err(|_| ())?;
                }
            }
        }

        Ok(())
    }

    fn handle_unwrap_activation_key(&mut self, wrapped_activation_key: &[u8], quantification: u8) -> Result<(), ()> {
        // Get activation key
        let mut activation_key = Vec::new();
        activation_key.extend_from_slice(wrapped_activation_key).map_err(|_| ())?; // Vérification automatique du non-débordement

        // Get random
        let mut random = Random::new();
        self.get_randoms(activation_key.len(), quantification, &mut random)?;

        // Finalize protectedModel
        let protected_model = ProtectedModels { activation_key, random, quantification };
        self.protected_models.push(protected_model).map_err(|_| ())?;

        Ok(())
        // TODO :
        //      - Réceptionner la key wrappée
    }

    fn handle_derive_key(_activation_key: &[u8], _random: &[u8], _quantification: u8, out: &mut SkyldKey) -> Result<(), ()> {
        out.clear();

        let quantification_size = match _quantification {
            QUANTIFICATION_FLOAT16 => F16_SIZE,
            _ => F32_SIZE,
        };

        let activation_key_iter = _activation_key.chunks_exact(F32_SIZE);
        let random_iter = _activation_key.chunks_exact(quantification_size);

        let mut i_usbip = 0;
        for (activation_key_element, random_element) in activation_key_iter.zip(random_iter) {
            if (i_usbip == 13) { break; } // Because USB/IP crashes above, remove when using with true Nitrokey 3
            i_usbip += 1;
            let activation_key = f32::from_ne_bytes(activation_key_element.try_into().unwrap());

            let val_random = match _quantification {
                QUANTIFICATION_FLOAT16 => {
                    let bytes: [u8; F16_SIZE] = random_element.try_into().unwrap();
                    f16::from_bits(u16::from_ne_bytes(bytes)).to_f32()
                },
                _ => {
                    let bytes: [u8; F32_SIZE] = random_element.try_into().unwrap();
                    f32::from_ne_bytes(bytes)
                },
            };
        
            let resultat = activation_key / val_random;
            out.extend_from_slice(&resultat.to_ne_bytes())
                .map_err(|_| ())?;
        }

        Ok(())
    }
}

// 1. Déclaration de l'AID
impl<C> AidApp for SkyldApp<C> {
    fn aid(&self) -> Aid {
        Self::AID
    }
}

// 2. Trait ISO7816 / APDU App
impl<C: CryptoClient> ApduApp for SkyldApp<C> {
    // Appelée automatiquement lors de la sélection, pas besoin de faire quelque chose
    fn select(
        &mut self,
        _interface: Interface,
        _apdu: CommandView<'_>,
        _reply: &mut VecView<u8>,
    ) -> Result<(), Status> {
        Ok(())
    }

    fn deselect(&mut self) {}

    fn call(
        &mut self,
        _interface: Interface,
        command: CommandView<'_>,
        reply: &mut VecView<u8>,
    ) -> Result<(), Status> {
        let ins: u8 = command.instruction().into();

        match ins {
            // INS 0x01 : Unwrap activation key
            0x01 => {
                let float_mode: u8 = command.p1;
                self.handle_unwrap_activation_key(command.data(), float_mode)
                    .map_err(|_| Status::UnspecifiedCheckingError)?; // Convertit l'erreur le cas échéant
                Ok(())
            }
            // INS 0x02 : Dérivation de clé
            0x02 => {
                // reply.capacity() = 7 609, donc 7 607 octets libres
                let protected_model_index = command.p1 as usize;

                let protected_model = self
                    .protected_models
                    .get(protected_model_index)
                    .ok_or(Status::NotFound)?;

                Self::handle_derive_key(protected_model.activation_key.as_slice(), protected_model.random.as_slice(), protected_model.quantification, &mut self.buff_reply)
                    .map_err(|_| Status::ConditionsOfUseNotSatisfied)?;

                // We sent the part of the response < reply.capacity()
                let chunk_size = core::cmp::min(reply.capacity(), self.buff_reply.len());

                reply.extend_from_slice(&self.buff_reply[0..chunk_size])
                    .map_err(|_| Status::UnspecifiedCheckingError)?;

                Ok(())
            }
            _ => Err(Status::InstructionNotSupportedOrInvalid),
        }
    }
}