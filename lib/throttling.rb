module ED2K
  # A [token bucket](https://en.wikipedia.org/wiki/Token_bucket) used to enforce an optional transfer rate limit.
  #
  # Tokens are bytes. They accrue at a constant rate up to a maximum (the bucket's capacity), and are spent by whoever
  # wants to transfer data. When the bucket runs dry the transfer has to wait for it to refill, which is what caps the
  # rate. The accrual is computed **lazily**, i.e. only when the bucket is actually consulted, so an idle core does no
  # bookkeeping at all and there's no timer or periodic sweep involved.
  #
  # The bucket starts empty, which matters: since it can never hand out more than it has accrued, the total transferred
  # over any period starting from creation is bounded by `rate * elapsed`, with no initial burst inflating it.
  #
  # The capacity is what the bucket may accumulate while nobody is spending, and it exists to avoid *under*-using the
  # allowance: if the socket thread is busy for a while, tokens keep accruing meanwhile and the traffic that was held up
  # can catch up afterwards. Too small a capacity would silently cap the achievable rate below the configured limit
  # whenever a round takes longer than usual, so it's deliberately a good fraction of a second's worth of traffic.
  #
  # A rate of `0` means unlimited, and is special-cased everywhere to cost essentially nothing: no clock is read and no
  # arithmetic is done, {#take} simply hands back whatever was asked for.
  class TokenBucket

    BURST_TIME   = 0.25 # Seconds worth of traffic the bucket may accumulate while idle
    MIN_CAPACITY = 4096 # Capacity floor in bytes, so that very low rates still make reasonable progress per round
    GRANT_RATIO  = 0.25 # Smallest useful grant, as a fraction of the capacity (see {#take})

    # The rate limit in bytes per second, or `0` if unlimited.
    # @return [Integer]
    attr_reader :rate

    # @param rate [Integer] The rate limit to enforce, in bytes per second. `0` means unlimited.
    def initialize(rate = 0)
      self.rate = rate
    end

    # Change the rate limit, resetting the bucket. Any tokens accrued under the old rate are dropped, so that a change
    # takes effect immediately rather than being preceded by a burst at the previous allowance.
    # @param rate [Integer] The new rate limit in bytes per second. `0` means unlimited.
    def rate=(rate)
      @rate     = rate.to_i
      @rate     = 0 if @rate < 0
      @capacity = @rate > 0 ? [(@rate * BURST_TIME).round, MIN_CAPACITY].max : 0
      @minimum  = [(@capacity * GRANT_RATIO).ceil, 1].max
      @tokens   = 0.0
      # Tokens accrue from the moment the limit is set rather than from the first transfer, so that a core which sits
      # idle for a while starts out with its allowance ready instead of having to earn it from scratch
      @time     = @rate > 0 ? Process.clock_gettime(Process::CLOCK_MONOTONIC) : nil
    end

    # Whether this bucket is actually enforcing a limit.
    # @return [Boolean] `true` if a rate limit is set, `false` if unlimited.
    def limited?
      @rate > 0
    end

    # Spend as many tokens as are available, up to the requested amount. The caller should transfer no more bytes than
    # the returned amount, and hand back whatever it didn't use with {#refund}.
    #
    # Nothing is granted until a worthwhile amount has accrued. Handing out the single byte that's available a few
    # microseconds after the last transfer would be technically correct but ruinous in practice: the socket thread would
    # wake thousands of times a second to move almost nothing, burning a whole CPU to enforce a modest limit. Batching
    # into chunks costs nothing in accuracy, since the average rate is set by how fast tokens accrue, not by how they're
    # handed out.
    # @param max [Integer] The most the caller would like to transfer, in bytes.
    # @return [Integer] How many bytes the caller may transfer, possibly `0`.
    def take(max)
      return max if @rate == 0
      refill()
      return 0 if @tokens < @minimum
      granted = [max, @tokens.floor].min
      @tokens -= granted
      granted
    end

    # Return tokens that were granted but ultimately not spent, e.g. because the peer had less data available than we
    # were willing to read. Without this a slow peer would consume the whole allowance of a round without using it, and
    # the achieved rate would sit well below the configured limit.
    # @param bytes [Integer] How many of the granted bytes went unused.
    def refund(bytes)
      return if @rate == 0 || bytes <= 0
      @tokens = [@tokens + bytes, @capacity].min
    end

    # Account for traffic that was already transferred without asking first, which is the case for UDP: datagrams arrive
    # whether we want them or not, and holding them back would break the protocol's timing rather than save bandwidth.
    # The bucket is allowed to go into debt here, and the gated TCP traffic then pays it back by waiting longer, which
    # keeps the overall limit honest.
    # @param bytes [Integer] How many bytes were transferred.
    def deduct(bytes)
      return if @rate == 0 || bytes <= 0
      refill()
      @tokens -= bytes
    end

    # How long until this bucket has something worthwhile to give, i.e. until {#take} would grant anything. Used to
    # decide how long the socket thread may sleep while throttled, so that it wakes up exactly when it can transfer
    # again instead of spinning or oversleeping.
    # @return [Float] Seconds until the next grant, `0.0` if one is available right now.
    def wait_time
      return 0.0 if @rate == 0
      refill()
      return 0.0 if @tokens >= @minimum
      (@minimum - @tokens) / @rate
    end

    private

    # Accrue the tokens earned since we last looked. This is the only place the clock is read, and it's only reached
    # when a limit is actually set.
    def refill
      now = Process.clock_gettime(Process::CLOCK_MONOTONIC)
      @time ||= now
      elapsed = now - @time
      return if elapsed <= 0
      @time = now
      @tokens = [@tokens + elapsed * @rate, @capacity.to_f].min
    end

  end
end
