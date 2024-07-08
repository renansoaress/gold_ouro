import express, { Express, Request, Response } from 'express';
import dotenv from 'dotenv';
import CryptoJS from 'crypto-js';
import * as fs from 'fs';
import * as path from 'path';
import { Buffer } from 'buffer';
import * as net from 'net';
import dgram from 'node:dgram';
import * as aesjs from 'aes-js';

dotenv.config();

const app: Express = express();
const port = process.env.PORT || 4000;
const GOKEY = 'minha senha secreta';

function asciiToBase64(input: string): string {
  return btoa(input);
}

function hexToAscii(input: string): string {
  const buffer = Buffer.from(input, 'hex');
  return buffer.toString('ascii');
}

function generateRandomNumber(): number {
  return Math.floor(Math.random() * 99999999999999);
}

function encryptText(plaintext: string, key: string, iv: string) {
  const sha256_key = CryptoJS.SHA256(key);
  const md5_iv = CryptoJS.MD5(iv);

  // console.log(`SHA256 Key: (${sha256_key.toString(CryptoJS.enc.Hex)})`);
  // console.log(`MD5 IV: (${md5_iv.toString(CryptoJS.enc.Hex)})`);

  const encrypted = CryptoJS.AES.encrypt(plaintext, sha256_key, { mode: CryptoJS.mode.CBC, iv: md5_iv });
  return encrypted;
}

function decryptText(encryptedHex: string, key: string, iv: string) {
  const sha256_key = CryptoJS.SHA256(key);
  const md5_iv = CryptoJS.MD5(iv);
  const encrypted = CryptoJS.enc.Hex.parse(encryptedHex);
  const cipherParams = CryptoJS.lib.CipherParams.create({
    ciphertext: encrypted,
  });

  const decrypted = CryptoJS.AES.decrypt(cipherParams, sha256_key, { mode: CryptoJS.mode.CBC, iv: md5_iv });
  return decrypted.toString(CryptoJS.enc.Utf8);
}

app.get('/:msg', (req: Request, res: Response) => {
  const { msg } = req.params;

  const randomNumber = generateRandomNumber();
  const iv = randomNumber.toString(16).toUpperCase().padStart(14, '0');
  const iv_go = `GOLD${iv}OURO`;

  const encrypted = encryptText(msg, GOKEY, iv_go);
  // console.log(`Base64 encoded output[${encrypted.toString().length}]: ${encrypted.toString()}`);

  // 0x5E; // ^ 0x24; // $
  let dataHex = encrypted.ciphertext.toString(CryptoJS.enc.Hex).toUpperCase();
  const dataAscii = hexToAscii(dataHex);
  const dataBase64 = asciiToBase64(dataAscii);
  console.log(`dataBase64 [${dataBase64.length}] :`, dataBase64);
  dataHex = '5E' + iv + dataHex + '24';
  console.log('DataHex :', dataHex);
  console.log('hexToAscii', hexToAscii(dataHex));

  //////////////////////////////////////////////////////////////////
  // Decrypt
  //////////////////////////////////////////////////////////////////

  const strData = hexToAscii(dataHex); // pronto para enviar
  const strDataBase64 = asciiToBase64(strData);
  const firstData = strData[0];
  const finalData = strData[strData.length - 1];
  const isValid = firstData === '^' && finalData === '$';
  if (isValid) {
    const iv_recv = dataHex.substring(2, 16);
    const iv = `GOLD${iv_recv}OURO`;
    const msg_recv = dataHex.substring(16, dataHex.length - 2);

    console.log(`SHA256 KEY (${CryptoJS.SHA256(GOKEY).toString()})`);
    console.log(`MD5 IV (${CryptoJS.MD5(iv).toString()})`);

    const decrypted = decryptText(msg_recv, GOKEY, iv);
    console.log(`${strData} Decrypted (${decrypted})`);

    res.send(
      `Encrypt Base64[${strDataBase64.length}](${strDataBase64})<br>Encrypt[${strData.length}](${strData}})<br>Decrypt[${decrypted.length}](${decrypted})`,
    );
  } else {
    res.send('?');
  }
});

app.listen(port, () => {
  console.log(`Server rodando na porta ${port} :D`);
});

// choco install netcat
// Server UDP // echo "Oiii tcp" | nc -w1 my.pc 4444
const portTCP = 4444;
const server = net.createServer((socket) => {
  // socket.setKeepAlive(true, 5000); // 1min
  console.log(`\n ${new Date().toJSON()} * Cliente conectado (TCP) * `);
  let count = 0;

  socket.setTimeout(60000);
  socket.on('timeout', () => {
    console.log('socket timeout');
    socket.destroy();
  });

  socket.on('data', async (data) => {
    //
    socket.write('ACK', async (err) => {
      if (err) {
        console.error(count, 'Erro ao enviar ACK!!!');
      }
    });

    console.log(
      `[${count}] ${new Date().toJSON()} - Recebido TCP: (${data.length})(${data.toString('hex').toUpperCase()})`,
    );

    const strData = data.toString();
    const firstData = strData[0];
    const finalData = strData[strData.length - 1];
    const isValid = firstData === '^' && finalData === '$';
    if (isValid) {
      const dataHex = data.toString('hex').toUpperCase();
      const iv_recv = dataHex.substring(2, 16);
      const iv = `GOLD${iv_recv}OURO`;
      const msg_recv = dataHex.substring(16, dataHex.length - 2);

      console.log(`SHA256 KEY (${CryptoJS.SHA256(GOKEY).toString()})`);
      console.log(`MD5 IV (${CryptoJS.MD5(iv).toString()})`);

      const decrypted = decryptText(msg_recv, GOKEY, iv);
      console.log(`${strData} Decrypted (${decrypted})`);
    }

    count++;
  });

  socket.on('end', () => {
    console.log(`[${count}] ${new Date().toJSON()} - Cliente disconectado TCP`);
  });

  socket.on('error', (error) => {
    // socket.end();
    console.error(`[${count}] ${new Date().toJSON()} - Socket Error TCP: ${error.name} - ${error.message}`);
  });

  socket.on('close', (error) => {
    const bread = socket.bytesRead;
    const bwrite = socket.bytesWritten;
    console.log('Bytes read : ' + bread);
    console.log('Bytes written : ' + bwrite);
    console.log('Socket closed!');
    if (error) {
      console.log('Socket was closed coz of transmission error');
    }
  });
});

server.on('error', (error) => {
  console.error(`${new Date().toJSON()} - Server Error TCP: ${error.message}`);
});

server.listen(portTCP, async () => {
  console.log(`TCP socket server ligado | Porta: ${portTCP}`);
});

// Server UDP // echo "Oiii udp" | nc -u -w1 my.pc 2222
const portUDP = 2222;
const serverUDP = dgram.createSocket('udp4', (msg, rinfo) => {
  console.log('\n * Cliente conectado (UDP)');
});

serverUDP.on('error', (err) => {
  console.error(`Server UDP error: ${err.stack}`);
  serverUDP.close();
});

serverUDP.on('close', () => {
  console.log(`Cliente disconectado UDP`);
});

serverUDP.on('message', async (data, rinfo) => {
  serverUDP.send('ACK', rinfo.port, rinfo.address, async (err, bytes) => {
    if (err) {
      console.error(`Erro ACK ${err.name}:${err.message}`);
    }
    console.log(`Recebido UDP: (${data.toString().length})(${data.toString()})`);
  });
});

serverUDP.on('listening', () => {
  const address = serverUDP.address();
  console.log(`UDP socket server ligado | Porta: ${address.port}`);
});

serverUDP.bind(portUDP);
