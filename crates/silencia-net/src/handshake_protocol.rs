// Direct peer-to-peer handshake protocol using libp2p request-response
// Replaces the broken gossipsub broadcast approach

use futures::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use libp2p::request_response::{self, ProtocolSupport};
use libp2p::StreamProtocol;
use std::io;
use tracing::{debug, error};

/// Protocol name for handshake request-response
pub const HANDSHAKE_PROTOCOL: &str = "/silencia/handshake/1.0.0";

async fn read_length_prefixed<T>(io: &mut T, max_size: usize) -> io::Result<Vec<u8>>
where
    T: AsyncRead + Unpin,
{
    // Read 4-byte length prefix
    let mut len_buf = [0u8; 4];
    io.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    
    if len > max_size {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Message too large: {} > {}", len, max_size),
        ));
    }
    
    // Read message bytes
    let mut buf = vec![0u8; len];
    io.read_exact(&mut buf).await?;
    Ok(buf)
}

async fn write_length_prefixed<T>(io: &mut T, data: &[u8]) -> io::Result<()>
where
    T: AsyncWrite + Unpin,
{
    // Write 4-byte length prefix
    let len = data.len() as u32;
    io.write_all(&len.to_be_bytes()).await?;
    
    // Write message bytes
    io.write_all(data).await?;
    Ok(())
}

/// Handshake request-response codec
#[derive(Debug, Clone, Default)]
pub struct HandshakeCodec;

/// Handshake request (INIT or RESP message bytes)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandshakeRequest(pub Vec<u8>);

/// Handshake response (RESP message bytes or ACK)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandshakeResponse(pub Vec<u8>);

#[async_trait::async_trait]
impl request_response::Codec for HandshakeCodec {
    type Protocol = StreamProtocol;
    type Request = HandshakeRequest;
    type Response = HandshakeResponse;

    async fn read_request<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
    ) -> io::Result<Self::Request>
    where
        T: AsyncRead + Unpin + Send,
    {
        debug!("📖 Reading handshake request from stream");
        let bytes = read_length_prefixed(io, 1024 * 1024).await?; // Max 1MB
        
        if bytes.is_empty() {
            error!("❌ Received empty handshake request");
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Empty handshake request",
            ));
        }
        
        debug!("✅ Read handshake request: {} bytes", bytes.len());
        Ok(HandshakeRequest(bytes))
    }

    async fn read_response<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
    ) -> io::Result<Self::Response>
    where
        T: AsyncRead + Unpin + Send,
    {
        debug!("📖 Reading handshake response from stream");
        let bytes = read_length_prefixed(io, 1024 * 1024).await?; // Max 1MB
        
        if bytes.is_empty() {
            error!("❌ Received empty handshake response");
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Empty handshake response",
            ));
        }
        
        debug!("✅ Read handshake response: {} bytes", bytes.len());
        Ok(HandshakeResponse(bytes))
    }

    async fn write_request<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
        req: Self::Request,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        debug!("📝 Writing handshake request: {} bytes", req.0.len());
        write_length_prefixed(io, &req.0).await?;
        io.close().await?;
        debug!("✅ Handshake request written and stream closed");
        Ok(())
    }

    async fn write_response<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
        res: Self::Response,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        debug!("📝 Writing handshake response: {} bytes", res.0.len());
        write_length_prefixed(io, &res.0).await?;
        io.close().await?;
        debug!("✅ Handshake response written and stream closed");
        Ok(())
    }
}

/// Create a request-response behaviour for handshakes
pub fn create_handshake_behaviour() -> request_response::Behaviour<HandshakeCodec> {
    request_response::Behaviour::new(
        [(StreamProtocol::new(HANDSHAKE_PROTOCOL), ProtocolSupport::Full)],
        request_response::Config::default()
            .with_request_timeout(std::time::Duration::from_secs(30)),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_handshake_request_creation() {
        let data = vec![1, 2, 3, 4, 5];
        let req = HandshakeRequest(data.clone());
        assert_eq!(req.0, data);
    }

    #[test]
    fn test_handshake_response_creation() {
        let data = vec![6, 7, 8, 9, 10];
        let resp = HandshakeResponse(data.clone());
        assert_eq!(resp.0, data);
    }
}
