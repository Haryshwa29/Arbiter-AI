/** Shared brand asset for every public website placement. */
export function ArbiterMark() {
  return <img className="arbiter-mark" src={`${import.meta.env.BASE_URL}arbiter-mark.svg?v=roman-shield`} width="40" height="40" alt="" aria-hidden="true" />;
}
