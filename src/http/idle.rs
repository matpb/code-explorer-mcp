//! Stream wrapper that fails reads and writes after a period with no progress in either direction.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::time::{Instant, Sleep};

pub(super) struct IdleStream<S> {
    inner: S,
    idle: Duration,
    timer: Pin<Box<Sleep>>,
}

impl<S> IdleStream<S> {
    pub(super) fn new(inner: S, idle: Duration) -> Self {
        IdleStream {
            inner,
            idle,
            timer: Box::pin(tokio::time::sleep(idle)),
        }
    }

    fn touch(&mut self) {
        self.timer.as_mut().reset(Instant::now() + self.idle);
    }

    fn poll_idle<T>(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<T>> {
        if self.timer.as_mut().poll(cx).is_ready() {
            Poll::Ready(Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "connection idle timeout",
            )))
        } else {
            Poll::Pending
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for IdleStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let before = buf.filled().len();
        match Pin::new(&mut this.inner).poll_read(cx, buf) {
            Poll::Ready(r) => {
                if buf.filled().len() > before {
                    this.touch();
                }
                Poll::Ready(r)
            }
            Poll::Pending => this.poll_idle(cx),
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for IdleStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_write(cx, data) {
            Poll::Ready(r) => {
                if matches!(r, Ok(n) if n > 0) {
                    this.touch();
                }
                Poll::Ready(r)
            }
            Poll::Pending => this.poll_idle(cx),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_write_vectored(cx, bufs) {
            Poll::Ready(r) => {
                if matches!(r, Ok(n) if n > 0) {
                    this.touch();
                }
                Poll::Ready(r)
            }
            Poll::Pending => this.poll_idle(cx),
        }
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
}
