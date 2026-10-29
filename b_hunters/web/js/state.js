/* The state the console keeps between views.
 *
 * The session, the current route and the live event stream are read by
 * modules that must not import each other: the api wrapper clears the
 * session, the router records the route and the stream owns the event
 * source.  One small module holds the shared object so that none of
 * them has to import the others.
 */

export const state = {
  user: null,
  csrf: null,
  route: 'dashboard',
  params: {},
  stream: null,
  lastSeq: 0,
  pollTimer: null,
  cache: {},
};
