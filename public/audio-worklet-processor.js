class AudioSenderProcessor extends AudioWorkletProcessor {
    constructor() {
        super();
        this.bufferSize = 4096;
        this.buffer = new Float32Array(this.bufferSize);
        this.writeIndex = 0;
    }

    process(inputs, outputs, parameters) {
        const input = inputs[0];
        if (!input || !input.length) return true;

        const channelData = input[0];
        if (!channelData) return true;

        if (this.writeIndex + channelData.length <= this.bufferSize) {
            this.buffer.set(channelData, this.writeIndex);
            this.writeIndex += channelData.length;
        } else {
            const spaceLeft = this.bufferSize - this.writeIndex;
            this.buffer.set(channelData.subarray(0, spaceLeft), this.writeIndex);
            this.writeIndex = this.bufferSize;
        }

        if (this.writeIndex >= this.bufferSize) {
            this.port.postMessage(this.buffer);
            this.writeIndex = 0;
        }

        return true;
    }
}

class AudioReceiverProcessor extends AudioWorkletProcessor {
    constructor() {
        super();
        this.buffer = [];
        this.currentFrame = null;
        this.readIndex = 0;

        this.port.onmessage = (e) => {
            if (e.data) {
                this.buffer.push(e.data);
                if (this.buffer.length > 50) {
                    this.buffer.shift();
                }
            }
        };
    }

    process(inputs, outputs, parameters) {
        const output = outputs[0];
        const channel = output[0];

        for (let i = 0; i < channel.length; i++) {
            if (!this.currentFrame || this.readIndex >= this.currentFrame.length) {
                if (this.buffer.length === 0) {
                    channel[i] = 0;
                    this.currentFrame = null;
                    continue;
                }
                this.currentFrame = this.buffer.shift();
                this.readIndex = 0;
            }

            channel[i] = this.currentFrame[this.readIndex] || 0;
            this.readIndex++;
        }

        return true;
    }
}

registerProcessor('audio-sender-processor', AudioSenderProcessor);
registerProcessor('audio-receiver-processor', AudioReceiverProcessor);
