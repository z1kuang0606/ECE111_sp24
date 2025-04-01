module bitcoin_hash_16 (input logic        clk, reset_n, start,
                     input logic [15:0] message_addr, output_addr,
                    output logic        done, mem_clk, mem_we,
                    output logic [15:0] mem_addr,
                    output logic [31:0] mem_write_data,
                     input logic [31:0] mem_read_data);

parameter num_nonces = 16;

//logic [ 4:0] state;
//logic [31:0] hout[num_nonces];

parameter int k[64] = '{
    32'h428a2f98,32'h71374491,32'hb5c0fbcf,32'he9b5dba5,32'h3956c25b,32'h59f111f1,32'h923f82a4,32'hab1c5ed5,
    32'hd807aa98,32'h12835b01,32'h243185be,32'h550c7dc3,32'h72be5d74,32'h80deb1fe,32'h9bdc06a7,32'hc19bf174,
    32'he49b69c1,32'hefbe4786,32'h0fc19dc6,32'h240ca1cc,32'h2de92c6f,32'h4a7484aa,32'h5cb0a9dc,32'h76f988da,
    32'h983e5152,32'ha831c66d,32'hb00327c8,32'hbf597fc7,32'hc6e00bf3,32'hd5a79147,32'h06ca6351,32'h14292967,
    32'h27b70a85,32'h2e1b2138,32'h4d2c6dfc,32'h53380d13,32'h650a7354,32'h766a0abb,32'h81c2c92e,32'h92722c85,
    32'ha2bfe8a1,32'ha81a664b,32'hc24b8b70,32'hc76c51a3,32'hd192e819,32'hd6990624,32'hf40e3585,32'h106aa070,
    32'h19a4c116,32'h1e376c08,32'h2748774c,32'h34b0bcb5,32'h391c0cb3,32'h4ed8aa4a,32'h5b9cca4f,32'h682e6ff3,
    32'h748f82ee,32'h78a5636f,32'h84c87814,32'h8cc70208,32'h90befffa,32'ha4506ceb,32'hbef9a3f7,32'hc67178f2
};

// Student to add rest of the code here

enum logic [2:0] {IDLE, READ, BLOCK, COMPUTE, PHASE2_3, WRITE} state;

logic [31:0] wt[16]; //only store the most recent 16 message schedules
logic [31:0] message[20]; //20 words
logic [31:0] h0, h1, h2, h3, h4, h5, h6, h7; //hash value for each block
logic [31:0] a, b, c, d, e, f, g, h; //
logic [ 7:0] i, j, p, t, l;
logic [15:0] offset; // in word address
logic [ 7:0] num_blocks;
logic        cur_we;
logic [15:0] cur_addr;
logic [31:0] cur_write_data;
//logic [512:0] memory_block;

logic [15:0] valid_all ;
logic [15:0] start_all ;
logic [31:0] hash_nonce_all[15:0]; //hash value from 16 instances
logic [3:0] nonce_all[15:0];
logic batch_num; //1 batches

logic [31:0] w_k_d;

/*logic [31:0] h0_p; //16 h0 of phase 2
logic [31:0] h1_p;
logic [31:0] h2_p;
logic [31:0] h3_p;
logic [31:0] h4_p;
logic [31:0] h5_p;
logic [31:0] h6_p;
logic [31:0] h7_p;*/

// SHA256 hash round
/*function logic [255:0] sha256_op(input logic [31:0] a, b, c, d, e, f, g, h, w,
                                 input logic [7:0] t);
    logic [31:0] S1, S0, ch, maj, t1, t2; // internal signals
	 begin
		 S1 = rightrotate(e, 6) ^ rightrotate(e, 11) ^ rightrotate(e, 25);
		 // Student to add remaning code below
		 // Refer to SHA256 discussion slides to get logic for this function
		 ch = (e & f) ^ ((~e) & g);
		 t1 = h + S1 + ch + k[t] + w;
		 S0 = rightrotate(a, 2) ^ rightrotate(a, 13) ^ rightrotate(a, 22);
		 maj = (a & b) ^ (a & c) ^ (b & c);
		 t2 = S0 + maj;
		 sha256_op = {t1 + t2, a, b, c, d + t1, e, f, g};
	 end
endfunction*/

/*function logic [255:0] sha256_op(input logic [31:0] a, b, c, d, e, f, g, h, w_k
                                 );
    logic [31:0] S1, S0, ch, maj, t1, t2; // internal signals
	 begin
		 S1 = rightrotate(e, 6) ^ rightrotate(e, 11) ^ rightrotate(e, 25);
		 // Student to add remaning code below
		 // Refer to SHA256 discussion slides to get logic for this function
		 ch = (e & f) ^ ((~e) & g);
		 t1 = h + S1 + ch + w_k;
		 S0 = rightrotate(a, 2) ^ rightrotate(a, 13) ^ rightrotate(a, 22);
		 maj = (a & b) ^ (a & c) ^ (b & c);
		 t2 = S0 + maj;
		 sha256_op = {t1 + t2, a, b, c, d + t1, e, f, g};
	 end
endfunction*/

function logic [255:0] sha256_op(input logic [31:0] a, b, c, d, e, f, g, w_k
                                 );
    logic [31:0] S1, S0, ch, maj, t1, t2; // internal signals
	 begin
		 S1 = rightrotate(e, 6) ^ rightrotate(e, 11) ^ rightrotate(e, 25);
		 // Student to add remaning code below
		 // Refer to SHA256 discussion slides to get logic for this function
		 ch = (e & f) ^ ((~e) & g);
		 t1 = S1 + ch + w_k;
		 S0 = rightrotate(a, 2) ^ rightrotate(a, 13) ^ rightrotate(a, 22);
		 maj = (a & b) ^ (a & c) ^ (b & c);
		 t2 = S0 + maj;
		 sha256_op = {t1 + t2, a, b, c, d + t1, e, f, g};
	 end
endfunction

function logic [31:0] wtnew;  // function with no inputs
	begin
		logic [31:0] s0, s1;
		s0 = rightrotate(wt[1],7)^rightrotate(wt[1],18)^(wt[1]>>3);
		s1 = rightrotate(wt[14],17)^rightrotate(wt[14],19)^(wt[14]>>10);
		wtnew = wt[0] + s0 + wt[9] + s1;
	end
endfunction

// Generate request to memory
// for reading from memory to get original message
// for writing final computed has value
assign mem_clk = clk;
assign mem_addr = cur_addr + offset;
assign mem_we = cur_we;
assign mem_write_data = cur_write_data;

function logic [31:0] rightrotate(input logic [31:0] x,
                                  input logic [ 7:0] r);
   rightrotate = (x >> r) | (x << (32 - r));
endfunction

genvar k2;
generate
	for (k2=0; k2<16; k2=k2+1) begin : phase2_3
		simplified_sha256_opt3 phase2_3_inst (
			.clk(clk),
			.reset_n(reset_n),
			.start(start_all[k2]),
			.hash_value({h7,h6,h5,h4,h3,h2,h1,h0}), //identical for all 8 instances
			.message_blocks({message[19],message[18],message[17],message[16]}),
			.nonce(nonce_all[k2]),
			.valid(valid_all[k2]),
			.hash_nonce(hash_nonce_all[k2])
		);
	end
endgenerate

always_comb begin
	for (int i=0; i<16; i=i+1) begin
		nonce_all[i] = i;
	end
end


always_ff @(posedge clk, negedge reset_n)
begin

	if (!reset_n) begin
		cur_we <= 1'b0;
		state <= IDLE;
	end
	else begin
		case(state)
			IDLE : begin
				if (start) begin
					h0 <= 32'h6a09e667;
					h1 <= 32'hbb67ae85;
					h2 <= 32'h3c6ef372;
					h3 <= 32'ha54ff53a;
					h4 <= 32'h510e527f;
					h5 <= 32'h9b05688c;
					h6 <= 32'h1f83d9ab;
					h7 <= 32'h5be0cd19;
					
					/*a <= 32'h6a09e667;
					b <= 32'hbb67ae85;
					c <= 32'h3c6ef372;
					d <= 32'ha54ff53a;
					e <= 32'h510e527f;
					f <= 32'h9b05688c;
					g <= 32'h1f83d9ab;
					h <= 32'h5be0cd19;*/
					
					cur_we <= 1'b0; //read
					cur_addr <= message_addr;
					offset <= 16'h0000;
					//i <= 0; //index for 64 rounds of word expansion and SHA256 operation
					j <= 1; //first block
					p <= 0;
					
					
					//l <= 0;
					
					state <= BLOCK;
				end
			end
			/*READ : begin
				if (offset < (19 + 1)) begin
					if (offset == 0) begin
						offset <= offset + 1;
						state <= READ;
					end
				else begin
					message[offset-1] <= mem_read_data;
					offset <= offset + 1;
					state <= READ;
				end
				end
				else begin
					offset <= 16'h0000;
					//message[19] <= 32'b0; //initialize nonce
					state <= BLOCK;
				end
			end*/
			BLOCK : begin
				//i <= 0;	
				if (offset == 0 && j != 2) begin
						offset <= offset + 1;						
				end
				/*else begin
					message[offset-1] <= mem_read_data;
					offset <= offset + 1;					
				end*/
				
				
				t <= 0;
				l <= 0;
				if (j == 1) begin //phase 1
					//memory_block <= {message[15], message[14], message[13], message[12], message[11], message[10], message[9], message[8],
						//			  message[7], message[6], message[5], message[4], message[3], message[2], message[1], message[0]}; //the first block consists of 16 words.	 message[(16*1 - 1) : 16 * (1 - 1)];
					{a,b,c,d,e,f,g,h} <= {h0,h1,h2,h3,h4,h5,h6,h7};					
					//j <= j + 1;
					state <= COMPUTE;
				end
				else begin //phase 2,3
					j <= 1;
					state <= PHASE2_3;
				end
			end
			COMPUTE : begin //compute first phase
				if (offset < (19 + 1)) begin
					message[offset-1] <= mem_read_data;
					offset <= offset + 1;					
				end
				/*else begin
					offset <= 16'h0000;
					//message[19] <= 32'b0; //initialize nonce
					
				end*/
				if (offset > 1) begin
					if (t < 64) begin
					  if (t < 16) begin
								//wt[t] <= memory_block[32*(t+1)-1 -: 32];
								wt[t] <= message[t];
								if (t == 1) begin
									w_k_d <= wt[t-1] + k[t-1] + h;
								end
								else if (t > 1) begin
									w_k_d <= wt[t-1] + k[t-1] + g;
									{a, b, c, d, e, f, g, h} <= sha256_op(a,b,c,d,e,f,g,w_k_d);
									//w_k_d <= wt[t-1] + k[t-1];							
								end
								/*if (t > 0) begin
									{a, b, c, d, e, f, g, h} <= sha256_op(a,b,c,d,e,f,g,h,wt[t-1],t-1);
								end*/
						end		
						else begin
							w_k_d <= wt[15] + k[t-1] + g;
							{a, b, c, d, e, f, g, h} <= sha256_op(a,b,c,d,e,f,g,w_k_d);
						
							for (int n = 0; n < 15; n++) wt[n] <= wt[n+1]; // just wires
							wt[15] <= wtnew();
							
							
						end
						
						t <= t + 1;
						state <= COMPUTE;
					end
					else if (t == 64) begin //SHA256 operation
						//{a, b, c, d, e, f, g, h} <= sha256_op(a,b,c,d,e,f,g,h,wt[15],t-1);
						//{a, b, c, d, e, f, g, h} <= sha256_op(a,b,c,d,e,f,g,h,w[t-1],t-1);
						w_k_d <= wt[15] + k[t-1] + g;
						{a, b, c, d, e, f, g, h} <= sha256_op(a,b,c,d,e,f,g,w_k_d);
						t <= t + 1;
						state <= COMPUTE;
					
					end
					else if (t == 65) begin
						{a, b, c, d, e, f, g, h} <= sha256_op(a,b,c,d,e,f,g,w_k_d);
						t <= t + 1;
						state <= COMPUTE;
					end
					else begin
					  h0 <= h0 + a;
					  h1 <= h1 + b;
					  h2 <= h2 + c;
					  h3 <= h3 + d;
					  h4 <= h4 + e;
					  h5 <= h5 + f;
					  h6 <= h6 + g;
					  h7 <= h7 + h;
					  j <= j + 1;
					  offset <= 16'h0000;
					  state <= BLOCK;
						
					end
				end
			end
			PHASE2_3 : begin //start submodules
				if (l == 0) begin
					start_all <= 16'hffff;
					l <= l + 1;
					state <= PHASE2_3;
				end
				else if (l == 1) begin
					start_all <= 16'h0000;
					l <= l + 1;
					state <= PHASE2_3;
				end
				else begin					
					if (&valid_all) begin //all nonce completed
						state <= WRITE;
						l <= 0;
					end
					else begin						
						state <= PHASE2_3;
					end
				end
				/*start_all <= 16'hffff;
				if (&valid_all) begin //all nonce completed
					state <= WRITE;		
					start_all <= 16'h0000;
				end
				else begin						
					state <= PHASE2_3;
				end*/
					
					
				
				
			end
	
			WRITE : begin
				cur_we <= 1'b1; //write
				cur_addr <= output_addr;	
				case (p)
					0 : begin
						cur_write_data <= hash_nonce_all[0];
					end 
					1 : begin
						cur_write_data <= hash_nonce_all[1];
					end
					2 : begin
						cur_write_data <= hash_nonce_all[2];
					end
					3 : begin
						cur_write_data <= hash_nonce_all[3];
					end
					4 : begin
						cur_write_data <= hash_nonce_all[4];
					end
					5 : begin
						cur_write_data <= hash_nonce_all[5];
					end
					6 : begin
						cur_write_data <= hash_nonce_all[6];
					end
					7 : begin
						cur_write_data <= hash_nonce_all[7];
					end
					8 : begin
						cur_write_data <= hash_nonce_all[8];
					end 
					9 : begin
						cur_write_data <= hash_nonce_all[9];
					end
					10 : begin
						cur_write_data <= hash_nonce_all[10];
					end
					11 : begin
						cur_write_data <= hash_nonce_all[11];
					end
					12 : begin
						cur_write_data <= hash_nonce_all[12];
					end
					13 : begin
						cur_write_data <= hash_nonce_all[13];
					end
					14 : begin
						cur_write_data <= hash_nonce_all[14];
					end
					15 : begin
						cur_write_data <= hash_nonce_all[15];
					end
					default : begin
						cur_write_data <= 0;
					end
				endcase	
				
				if (p == 0) begin
					p <= p + 1;
					state <= WRITE;
				end		
				else if (p < 16) begin
					p <= p + 1;
					offset <= offset + 1;
					state <= WRITE;
				end		
				else begin					
					p <= 0;
					cur_we <= 1'b0;
					
					offset <= 0;						
					state <= IDLE;
					
				end
			end
			default : begin
				state <= IDLE;
			end
		endcase
	end
end

// Generate done when SHA256 hash computation has finished and moved to IDLE state
assign done = (state == IDLE);

endmodule
