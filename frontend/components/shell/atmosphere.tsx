/** Fixed full-viewport backdrop: ambient light (CSS drift), static grain, vignette. */
export function Atmosphere() {
  return (
    <div aria-hidden className="atmosphere">
      <div className="atmosphere-light a" />
      <div className="atmosphere-light b" />
      <div className="atmosphere-grain" />
      <div className="atmosphere-vignette" />
    </div>
  );
}
