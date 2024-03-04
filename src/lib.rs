


///! vhost
///
///!  vhost is to fetch sni info and return value is still available
///
///! # Example
/// ```
/// let tls_conn = ShareConn::new(conn);
/// let sni = tls_conn.get_sni();
/// assert!("google.com", sni);
/// ```

pub mod vhost {
    use std::io::{self, Cursor, Read, Write};
    use std::net::TcpStream;
    use std::sync::{Arc, Mutex};

    pub struct SharedConn {
        pub stream: TcpStream,
        buffer: Arc<Mutex<Cursor<Vec<u8>>>>,

        sni: String,
    }

    impl SharedConn {
        pub fn new(mut stream: TcpStream) -> Result<SharedConn, std::io::Error> {
            let buffer = Arc::new(Mutex::new(Cursor::new(Vec::new())));

            // read tls handshake from stream, and then put data into buffer
            let mut buf: [u8; 1024] = [0_u8; 1024];
            let n = stream.read(&mut buf)?;
            if n > 0 {
                let mut buffer = buffer.lock().unwrap();
                buffer.get_mut().extend_from_slice(&buf[..n]);
            }

            let sni = parse_sni(&buf, n)?;

            Ok(SharedConn {
                stream,
                buffer,
                sni,
            })
        }

        pub fn get_sni(&self) -> String {
            self.sni.clone()
        }
    }

    impl Read for SharedConn {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let mut buffer = self.buffer.lock().unwrap();
            if buffer.position() < buffer.get_ref().len() as u64 {
                buffer.read(buf)
            } else {
                self.stream.read(buf)
            }
        }
    }

    impl Write for SharedConn {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.stream.write(buf)
        }

        // 实现flush方法
        fn flush(&mut self) -> io::Result<()> {
            // 同样，这里简单地将标准输出的缓冲区刷新，实际应用中应根据需要进行操作
            self.stream.flush()
        }
    }

    fn parse_sni(buf: &[u8], n: usize) -> Result<String, io::Error> {
        // 提取出 server name
        if n < 42 {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "tls handshake is too short",
            ));
        }

        let mut m: String = "".to_string();

        //m.vers = (buf[4] << 8 | buf[5]) as u16;

        let session_id_len = buf[43] as usize;
        if n < 44 + session_id_len {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "tls handshake is too short",
            ));
        }

        let mut cur = 44 + session_id_len;
        if n < cur + 2 {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "tls handshake is too short",
            ));
        }

        let cipher_suites_len = ((buf[cur] as usize) << 8 | buf[cur + 1] as usize) as usize;
        if n < cur + 2 + cipher_suites_len {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "tls handshake is too short",
            ));
        }
        cur = cur + 2 + cipher_suites_len;

        let compression_methods_len = buf[cur] as usize;
        if n < cur + 3 + cipher_suites_len + compression_methods_len {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "tls handshake is too short",
            ));
        }

        cur = cur + 1 + compression_methods_len;

        let extension_len = (buf[cur] as usize) << 8 | (buf[cur + 1] as usize);
        if n < cur + extension_len {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "tls handshake is too short",
            ));
        }

        cur = cur + 2;

        let mut ext_cur = 0;
        while ext_cur < extension_len {
            let ext_type = (buf[cur] as u16) << 8 | buf[cur + 1] as u16;
            let ext_len = (buf[cur + 2] as usize) << 8 | buf[cur + 3] as usize;
            if ext_type == 0 {
                m = String::from_utf8(buf[cur + 9..cur + 4 + ext_len].to_vec()).unwrap();
                break;
            }
            cur += 4 + ext_len;
            ext_cur += 4 + ext_len;
        }

        Ok(m)
    }
}

// 为上面的代码添加测试
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_sni() {
        // 监听 443 端口，来获取 tls 握手信息
        use std::net::TcpListener;
        let listener = TcpListener::bind("0.0.0.0:443").unwrap();
        let (stream, _) = listener.accept().unwrap();
        let tls_conn = vhost::SharedConn::new(stream).unwrap();
        let sni = tls_conn.get_sni();
        // 添加  assert 确保 sni 为 www.baidu.com
        assert_eq!(sni, "www.baidu.com");

        // local test curl
        //  curl -vv --resolve www.baidu.com:443:127.0.0.1 https://www.baidu.com
    }
}
