module simplified_sha256_opt7 #(parameter integer NUM_OF_WORDS = 20)(
 input logic  clk, reset_n, start,
 input logic  [15:0] message_addr, output_addr,
 output logic done, mem_clk, mem_we, //mem_we : 1 = write, 0 = read
 output logic [15:0] mem_addr,
 output logic [31:0] mem_write_data,
 input logic [31:0] mem_read_data);

// FSM state variables 
enum logic [2:0] {IDLE, READ, BLOCK, COMPUTE, WRITE} state;
//localparam k = NUM_OF_WORDS * 32; //total bits
//localparam padz = 448 + ((1 + ))

// NOTE : Below mentioned frame work is for reference purpose.
// Local variables might not be complete and you might have to add more variables
// or modify these variables. Code below is more as a reference.

// Local variables
//logic [31:0] w[64]; //64 message schedules
logic [31:0] wt[16]; //only store the most recent 16 message schedules
logic [31:0] message[20]; //20 words
//logic [31:0] wt;  //one message schedule
logic [31:0] h0, h1, h2, h3, h4, h5, h6, h7; //hash value for each block
logic [31:0] a, b, c, d, e, f, g, h; //
logic [ 7:0] i, j, p, t;
logic [15:0] offset; // in word address
logic [ 7:0] num_blocks;
logic        cur_we;
logic [15:0] cur_addr;
logic [31:0] cur_write_data;
logic [512:0] memory_block;

int l;

logic [31:0] w_k_d;

// SHA256 K constants
parameter int k[0:63] = '{
   32'h428a2f98,32'h71374491,32'hb5c0fbcf,32'he9b5dba5,32'h3956c25b,32'h59f111f1,32'h923f82a4,32'hab1c5ed5,
   32'hd807aa98,32'h12835b01,32'h243185be,32'h550c7dc3,32'h72be5d74,32'h80deb1fe,32'h9bdc06a7,32'hc19bf174,
   32'he49b69c1,32'hefbe4786,32'h0fc19dc6,32'h240ca1cc,32'h2de92c6f,32'h4a7484aa,32'h5cb0a9dc,32'h76f988da,
   32'h983e5152,32'ha831c66d,32'hb00327c8,32'hbf597fc7,32'hc6e00bf3,32'hd5a79147,32'h06ca6351,32'h14292967,
   32'h27b70a85,32'h2e1b2138,32'h4d2c6dfc,32'h53380d13,32'h650a7354,32'h766a0abb,32'h81c2c92e,32'h92722c85,
   32'ha2bfe8a1,32'ha81a664b,32'hc24b8b70,32'hc76c51a3,32'hd192e819,32'hd6990624,32'hf40e3585,32'h106aa070,
   32'h19a4c116,32'h1e376c08,32'h2748774c,32'h34b0bcb5,32'h391c0cb3,32'h4ed8aa4a,32'h5b9cca4f,32'h682e6ff3,
   32'h748f82ee,32'h78a5636f,32'h84c87814,32'h8cc70208,32'h90befffa,32'ha4506ceb,32'hbef9a3f7,32'hc67178f2
};


assign num_blocks = determine_num_blocks(NUM_OF_WORDS); 
//assign tstep = (i - 1);

// Note : Function defined are for reference purpose. Feel free to add more functions or modify below.
// Function to determine number of blocks in memory to fetch
function logic [15:0] determine_num_blocks(input logic [31:0] size);

  // Student to add function implementation
   determine_num_blocks = (size / 16) + 1;
	
endfunction


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

/*function logic [255:0] sha256_op_forward(input logic [31:0] a, b, c, d, e, f, g, h, w_k
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


// Right Rotation Example : right rotate input x by r
// Lets say input x = 1111 ffff 2222 3333 4444 6666 7777 8888
// lets say r = 4
// x >> r  will result in : 0000 1111 ffff 2222 3333 4444 6666 7777 
// x << (32-r) will result in : 8888 0000 0000 0000 0000 0000 0000 0000
// final right rotate expression is = (x >> r) | (x << (32-r));
// (0000 1111 ffff 2222 3333 4444 6666 7777) | (8888 0000 0000 0000 0000 0000 0000 0000)
// final value after right rotate = 8888 1111 ffff 2222 3333 4444 6666 7777
// Right rotation function
function logic [31:0] rightrotate(input logic [31:0] x,
                                  input logic [ 7:0] r);
   rightrotate = (x >> r) | (x << (32 - r));
endfunction


// SHA-256 FSM 
// Get a BLOCK from the memory, COMPUTE Hash output using SHA256 function
// and write back hash value back to memory
always_ff @(posedge clk, negedge reset_n)
begin
  if (!reset_n) begin
    cur_we <= 1'b0;
    state <= IDLE;
  end 
  else case (state)
    // Initialize hash values h0 to h7 and a to h, other variables and memory we, address offset, etc
    IDLE: begin 
       if(start) begin
       // Student to add rest of the code  
		   h0 <= 32'h6a09e667;
			h1 <= 32'hbb67ae85;
			h2 <= 32'h3c6ef372;
			h3 <= 32'ha54ff53a;
			h4 <= 32'h510e527f;
			h5 <= 32'h9b05688c;
			h6 <= 32'h1f83d9ab;
			h7 <= 32'h5be0cd19;
			
			
			
			
			cur_we <= 1'b0; //read
			cur_addr <= message_addr;
			offset <= 16'h0000;
			//i <= 0; //index for 64 rounds of word expansion and SHA256 operation
			j <= 1; //first block
			p <= 0;
			
			state <= BLOCK;

       end
    end
	 

    // SHA-256 FSM 
    // Get a BLOCK from the memory, COMPUTE Hash output using SHA256 function    
    // and write back hash value back to memory
	/* READ : begin
			
			if (offset < (NUM_OF_WORDS + 1)) begin
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
				state <= BLOCK;
			end
			
	 end*/
    BLOCK: begin
	// Fetch message in 512-bit block size
	// For each of 512-bit block initiate hash value computation, do block pre-process
		//i <= 0;	
		
		if (offset == 0 && j == 1) begin
			offset <= offset + 1;						
		end
		
		t <= 0;
		//w_k_d <= 0;
		if (j < num_blocks + 1) begin
         if (j == num_blocks) begin //final block, need padding
				//memory_block <= {message[(NUM_OF_WORDS - 1) : (NUM_OF_WORDS - (NUM_OF_WORDS % 16))], 1'b1, {319{1'b0}}, 64'h0000000000000280};
				//memory_block <= {message[19], message[18], message[17], message[16], 1'b1, {319{1'b0}}, 64'h0000000000000280};
				//memory_block <= {64'h0000028000000000,{319{1'b0}},1'b1,message[19], message[18], message[17], message[16]};
				memory_block <= {32'd640,{10{32'h00000000}},32'h80000000,message[19], message[18], message[17], message[16]};
				{a,b,c,d,e,f,g,h} <= {h0,h1,h2,h3,h4,h5,h6,h7};
				j <= j + 1;
			end
			else begin
				//memory_block <= {message[15], message[14], message[13], message[12], message[11], message[10], message[9], message[8],
					//				  message[7], message[6], message[5], message[4], message[3], message[2], message[1], message[0]}; //the first block consists of 16 words.	 message[(16*1 - 1) : 16 * (1 - 1)];
				{a,b,c,d,e,f,g,h} <= {h0,h1,h2,h3,h4,h5,h6,h7};
				j <= j + 1;
			end
			state <= COMPUTE;
		end
		else begin
			offset <= 16'h0000;
			state <= WRITE;
		end   
    end

    // For each block compute hash function
    // Go back to BLOCK stage after each block hash computation is completed and if
    // there are still number of message blocks available in memory otherwise
    // move to WRITE stage
    COMPUTE: begin
	// 64 processing rounds steps for 512-bit block
		  //word expansion
		  
		  if (offset < (20 + 1)) begin
				message[offset-1] <= mem_read_data;
				offset <= offset + 1;					
			end
		  
		  if (offset > 1) begin
			  if (t < 64) begin
				  if (t < 16) begin
							//wt[t] <= memory_block[32*(t+1)-1 -: 32];
							if (j == 2) begin
								wt[t] <= message[t];
							end
							else if (j == 3) begin
								wt[t] <= memory_block[32*(t+1)-1 -: 32];
							end
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
						w_k_d <= wt[15] + k[t-1] + g;
						{a, b, c, d, e, f, g, h} <= sha256_op(a,b,c,d,e,f,g,w_k_d);
						
						//{a, b, c, d, e, f, g, h} <= sha256_op(a,b,c,d,e,f,g,h,wt[15],t-1);	
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
				  //offset <= 16'h0000;
				  state <= BLOCK;
				end
			
		  end
	end

    // h0 to h7 each are 32 bit hashes, which makes up total 256 bit value
    // h0 to h7 after compute stage has final computed hash value
    // write back these h0 to h7 to memory starting from output_addr
    WRITE: begin
		cur_we <= 1'b1; //write
		cur_addr <= output_addr;	
			
		
			case (p)
			0 : begin
				cur_write_data <= h0;
			end 
			1 : begin
				cur_write_data <= h1;
			end
			2 : begin
				cur_write_data <= h2;
			end
			3 : begin
				cur_write_data <= h3;
			end
			4 : begin
				cur_write_data <= h4;
			end
			5 : begin
				cur_write_data <= h5;
			end
			6 : begin
				cur_write_data <= h6;
			end
			7 : begin
				cur_write_data <= h7;
			end
			default : begin
				cur_write_data <= 0;
			end
			endcase	
		
		if (p == 0) begin
			p <= p + 1;
			state <= WRITE;
		end		
		else if (p < 8) begin
			p <= p + 1;
			offset <= offset + 1;
			state <= WRITE;
		end		
		else begin
			offset <= 0;
			p <= 0;
			cur_we <= 1'b0;
			state <= IDLE;
		end						
    end
   default : begin
		state <= IDLE;
	end
	endcase
  end

// Generate done when SHA256 hash computation has finished and moved to IDLE state
assign done = (state == IDLE);

endmodule
