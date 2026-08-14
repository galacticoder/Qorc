class AudioSenderProcessor extends AudioWorkletProcessor {
    constructor() {
        super();
        this.active = true;
        this.bufferSize = 2048;
        this.buffer = new Float32Array(this.bufferSize);
        this.writeIndex = 0;
        this.port.onmessage = (event) => {
            if (event.data?.type !== 'destroy') return;
            this.buffer.fill(0);
            this.writeIndex = 0;
            this.active = false;
            this.port.close();
        };
    }

    process(inputs, outputs, parameters) {
        if (!this.active) return false;
        const input = inputs[0];
        if (!input || !input.length) return true;

        const channelData = input[0];
        if (!channelData) return true;

        let readIndex = 0;
        while (readIndex < channelData.length) {
            const writeLength = Math.min(
                this.bufferSize - this.writeIndex,
                channelData.length - readIndex
            );
            this.buffer.set(channelData.subarray(readIndex, readIndex + writeLength), this.writeIndex);
            this.writeIndex += writeLength;
            readIndex += writeLength;

            if (this.writeIndex >= this.bufferSize) {
                const completed = this.buffer;
                this.buffer = new Float32Array(this.bufferSize);
                this.writeIndex = 0;
                try {
                    this.port.postMessage(completed, [completed.buffer]);
                } catch {
                    completed.fill(0);
                }
            }
        }

        return true;
    }
}

class AudioReceiverProcessor extends AudioWorkletProcessor {
    constructor() {
        super();
        this.active = true;
        this.buffer = [];
        this.currentFrame = null;
        this.readIndex = 0;

        this.port.onmessage = (e) => {
            if (e.data?.type === 'destroy') {
                for (const frame of this.buffer) frame.fill(0);
                this.buffer = [];
                this.currentFrame?.fill(0);
                this.currentFrame = null;
                this.readIndex = 0;
                this.active = false;
                this.port.close();
                return;
            }
            if (!(e.data instanceof Float32Array) || e.data.length === 0) return;
            if (e.data.length > 16384) {
                e.data.fill(0);
                return;
            }
            this.buffer.push(e.data);
            if (this.buffer.length > 12) {
                const dropped = this.buffer.shift();
                if (dropped) dropped.fill(0);
            }
        };
    }

    process(inputs, outputs, parameters) {
        const output = outputs[0];
        if (!output || output.length === 0) return true;
        if (!this.active) {
            for (const channel of output) channel.fill(0);
            return false;
        }
        const channel = output[0];
        if (!channel) return true;

        for (let i = 0; i < channel.length; i++) {
            if (this.currentFrame && this.readIndex >= this.currentFrame.length) {
                this.currentFrame.fill(0);
                this.currentFrame = null;
                this.readIndex = 0;
            }
            if (!this.currentFrame) {
                if (this.buffer.length === 0) {
                    channel[i] = 0;
                    continue;
                }
                this.currentFrame = this.buffer.shift();
                this.readIndex = 0;
            }

            channel[i] = this.currentFrame[this.readIndex] || 0;
            this.readIndex++;
        }
        if (this.currentFrame && this.readIndex >= this.currentFrame.length) {
            this.currentFrame.fill(0);
            this.currentFrame = null;
            this.readIndex = 0;
        }

        return true;
    }
}

registerProcessor('audio-sender-processor', AudioSenderProcessor);
registerProcessor('audio-receiver-processor', AudioReceiverProcessor);
